// Local structural validator for the Pruvz Public Evidence Packet.
//
// Everything happens on this machine: the schemas are read from the local
// schema/ directory, validation runs in-process, and nothing — not the packet,
// not telemetry, not usage data — is sent anywhere. No Pruvz account, API key
// or network connection is required or used.
//
// Validation has two layers:
//   1. JSON Schema validation (Ajv, draft 2020-12) against the release
//      matching the packet's declared format version.
//   2. Packet-level consistency checks for the handful of cross-object rules
//      JSON Schema cannot express (equality between objects, uniqueness and
//      contiguity across an array, presence coupling between the action and
//      the timeline). A third-party validator using the schema files alone
//      will not catch these — that is exactly why this validator exists.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import { canonicalDecimal, isMoney } from './canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const schemaRoot = path.join(here, '..', 'schema')

/** Packet format versions this checkout can validate, newest first. */
export const SUPPORTED_VERSIONS = ['1.5.0', '1.4.0', '1.3.0', '1.2.0', '1.1.0', '1.0.0']

/**
 * Whether a format version includes the human-triggered re-verification model
 * (format 1.3.0): the Worker's own review transitions after a
 * RESOLVED_EXTERNALLY event, the FOLLOW_UP_INDEPENDENT_READBACK evidence type,
 * the fresh reverificationTiming window and the independentlyConfirmed marker.
 */
const supportsReverification = (version) => {
  const [major, minor] = version.split('.').map(Number)
  return major > 1 || (major === 1 && minor >= 3)
}

/**
 * Whether a format version carries the exact decimal representation of money
 * (format 1.4.0): every money value states its amount twice — as the JSON
 * number consumers display and as the exact canonical decimal string that
 * cryptographic commitments bind to.
 */
const supportsExactAmount = (version) => {
  const [major, minor] = version.split('.').map(Number)
  return major > 1 || (major === 1 && minor >= 4)
}

const compiled = new Map()

/**
 * Compiles (once per version) and returns the Ajv validate function for one
 * packet format version. Schema layer only — validatePacket() adds the
 * packet-level consistency layer.
 */
export function createValidator(version = SUPPORTED_VERSIONS[0]) {
  if (!SUPPORTED_VERSIONS.includes(version)) {
    throw new Error(
      `Unsupported packet format version "${version}". Supported: ${SUPPORTED_VERSIONS.join(', ')}.`,
    )
  }

  if (!compiled.has(version)) {
    const dir = path.join(schemaRoot, `v${version}`)
    const load = (name) => JSON.parse(readFileSync(path.join(dir, name), 'utf8'))

    const ajv = new Ajv2020({ allErrors: true, strict: true })
    addFormats(ajv)
    ajv.addSchema(load('action.schema.json'))
    ajv.addSchema(load('evidence.schema.json'))
    compiled.set(version, ajv.compile(load('evidence-packet.schema.json')))
  }

  return compiled.get(version)
}

const consistencyError = (instancePath, message) => ({
  instancePath,
  keyword: 'packetConsistency',
  message,
})

/**
 * Every money value inside a document, with the pointer that locates it. The
 * shape test is the committer's own, so "what is an amount" has exactly one
 * definition in this repository.
 */
const moneyValues = (value, pointer, found = []) => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => moneyValues(item, `${pointer}/${index}`, found))
  } else if (value !== null && typeof value === 'object') {
    if (isMoney(value)) {
      found.push({ pointer, money: value })
    }
    for (const key of Object.keys(value)) {
      moneyValues(value[key], `${pointer}/${key}`, found)
    }
  }
  return found
}

/**
 * Whether a money value's two representations denote the same amount: the JSON
 * number must be what a parser produces from the exact string.
 *
 * The comparison is numeric on purpose. A JSON number is a double, so above
 * double precision it can only be the *nearest* double to the exact amount —
 * comparing the printed forms instead would reject amounts this contract
 * explicitly admits (29 integer digits) merely for being larger than a double
 * can carry exactly. Below double precision no JSON number can witness the
 * exact value at all, which is the whole reason a commitment binds the string
 * and never the number.
 */
const representationsAgree = (money) => {
  try {
    return Number(canonicalDecimal(money.amountExact)) === money.amount
  } catch {
    return false
  }
}

/**
 * The cross-object rules of the packet format, checked only after the packet
 * is schema-valid (they assume the declared structure). Returns Ajv-shaped
 * error objects so the two layers report uniformly.
 */
export function packetConsistencyErrors(packet, version = SUPPORTED_VERSIONS[0]) {
  const errors = []
  const { action, evidence } = packet
  const items = evidence.items
  const reverification = supportsReverification(version)

  // The two packet parts must describe the same action.
  if (action.actionId !== evidence.actionId) {
    errors.push(
      consistencyError(
        '/evidence/actionId',
        `must equal /action/actionId ("${evidence.actionId}" vs "${action.actionId}")`,
      ),
    )
  }
  for (const [index, item] of items.entries()) {
    // Timeline sequences are allocated atomically per action starting at 1,
    // and the export reports them in sequence order — so in a packet they are
    // unique, ascending and contiguous: item i carries sequence i+1.
    if (item.sequence !== index + 1) {
      errors.push(
        consistencyError(
          `/evidence/items/${index}/sequence`,
          `must be ${index + 1}: timeline sequences are unique, ascending and contiguous from 1`,
        ),
      )
    }
  }

  const seenEvidenceIds = new Map()
  for (const [index, item] of items.entries()) {
    if (seenEvidenceIds.has(item.evidenceId)) {
      errors.push(
        consistencyError(
          `/evidence/items/${index}/evidenceId`,
          `must be unique: "${item.evidenceId}" already appears at item ${seenEvidenceIds.get(item.evidenceId)}`,
        ),
      )
    } else {
      seenEvidenceIds.set(item.evidenceId, index)
    }
  }

  const decisionItems = items.filter((item) => item.type === 'HUMAN_REVIEW_DECISION')
  if (action.review === undefined) {
    // Formats 1.0.0 and 1.1.0: a recorded human decision and the DECIDED
    // review state imply each other — the decision is appended as
    // HUMAN_REVIEW_DECISION evidence in the same consistency boundary that
    // flips the review state.
    if (action.reviewState === 'DECIDED' && decisionItems.length === 0) {
      errors.push(
        consistencyError(
          '/action/reviewState',
          'DECIDED requires a HUMAN_REVIEW_DECISION item on the evidence timeline',
        ),
      )
    }
    if (decisionItems.length > 0 && action.reviewState !== 'DECIDED') {
      errors.push(
        consistencyError(
          '/action/reviewState',
          `must be DECIDED when the timeline carries a HUMAN_REVIEW_DECISION item (got ${action.reviewState})`,
        ),
      )
    }
  } else {
    errors.push(...reviewConsistencyErrors(action, decisionItems, reverification))
  }

  // Format 1.3.0: a follow-up independent read-back and a recorded fresh
  // window both exist only inside a human-triggered re-verification — which
  // only a RESOLVED_EXTERNALLY review event can open.
  const resolvedExternally =
    action.review != null &&
    action.review.decisions.some((decision) => decision.decision === 'RESOLVED_EXTERNALLY')
  if (reverification && action.reverificationTiming != null && !resolvedExternally) {
    errors.push(
      consistencyError(
        '/action/reverificationTiming',
        'a recorded re-verification window requires a RESOLVED_EXTERNALLY decision in the review history — only that event opens one',
      ),
    )
  }
  if (reverification && items.some((item) => item.type === 'FOLLOW_UP_INDEPENDENT_READBACK')) {
    if (!resolvedExternally) {
      errors.push(
        consistencyError(
          '/action/review',
          'FOLLOW_UP_INDEPENDENT_READBACK evidence requires a RESOLVED_EXTERNALLY decision in the review history',
        ),
      )
    }
    if (action.reverificationTiming == null) {
      errors.push(
        consistencyError(
          '/action/reverificationTiming',
          'FOLLOW_UP_INDEPENDENT_READBACK evidence requires the fresh re-verification window to be recorded',
        ),
      )
    }
  }

  // Execution state and its timestamps must agree. COMPLETED does not require
  // executionStartedAtUtc: the completion transition is legal straight from
  // RECEIVED when the agent never reported an execution start.
  const { executionStatus, executionStartedAtUtc, executionCompletedAtUtc } = action
  if (executionStatus === 'RECEIVED' && executionStartedAtUtc !== null) {
    errors.push(
      consistencyError(
        '/action/executionStartedAtUtc',
        'must be null while executionStatus is RECEIVED',
      ),
    )
  }
  if (executionStatus === 'EXECUTING' && executionStartedAtUtc === null) {
    errors.push(
      consistencyError(
        '/action/executionStartedAtUtc',
        'must be set when executionStatus is EXECUTING',
      ),
    )
  }
  if (executionStatus === 'COMPLETED' && executionCompletedAtUtc === null) {
    errors.push(
      consistencyError(
        '/action/executionCompletedAtUtc',
        'must be set when executionStatus is COMPLETED',
      ),
    )
  }
  if (executionStatus !== 'COMPLETED' && executionCompletedAtUtc !== null) {
    errors.push(
      consistencyError(
        '/action/executionCompletedAtUtc',
        `must be null while executionStatus is ${executionStatus}`,
      ),
    )
  }

  // A verification job exists only once execution completed, so any
  // verification state past NOT_STARTED implies COMPLETED execution.
  if (action.verificationStatus !== 'NOT_STARTED' && executionStatus !== 'COMPLETED') {
    errors.push(
      consistencyError(
        '/action/verificationStatus',
        `${action.verificationStatus} requires executionStatus COMPLETED (got ${executionStatus})`,
      ),
    )
  }

  // Format 1.1.0: an absent-after-deadline mismatch is only possible when an
  // explicit verification deadline was resolved (fields absent on 1.0.0
  // packets, where this rule simply never fires). A null verificationTiming is
  // exempt on purpose: the schema admits it exactly for action records that
  // predate the timing model, whose historical mismatches may carry this
  // category without a recorded resolution — the rule binds every record the
  // timing model actually covers.
  if (
    action.mismatch &&
    action.mismatch.mismatchReason === 'EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE' &&
    action.verificationTiming &&
    action.verificationTiming.deadlineAtUtc === null
  ) {
    errors.push(
      consistencyError(
        '/action/mismatch/mismatchReason',
        'EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE requires a resolved verificationTiming.deadlineAtUtc',
      ),
    )
  }

  // Format 1.4.0: a money value states its amount twice, and a cryptographic
  // commitment binds only the exact string (see docs/COMMITMENT.md). A packet
  // whose display number disagrees with its exact amount would therefore still
  // satisfy its commitment while showing a reader something else — so the
  // disagreement itself has to be rejected here.
  if (supportsExactAmount(version)) {
    for (const { pointer, money } of moneyValues(action, '/action')) {
      if (!representationsAgree(money)) {
        errors.push(
          consistencyError(
            `${pointer}/amountExact`,
            `must denote the same amount as the JSON number beside it ` +
              `(${money.amount} vs "${money.amountExact}")`,
          ),
        )
      }
    }
  }

  return errors
}

/**
 * Format 1.2.0: the review block, the review state and the timeline's
 * HUMAN_REVIEW_DECISION items are three views of one append-only record and
 * must agree. The review's decision history is exactly the timeline's
 * decision items, in order; the current disposition is the last of them (or
 * null when there is none); and the review state is where the last decision
 * moved the review — PENDING_REVIEW while no decision was recorded.
 *
 * Format 1.3.0 adds the Worker's own transitions after a RESOLVED_EXTERNALLY
 * event, which append no decision entry: the re-verification may return the
 * review to PENDING_REVIEW (a new non-verified ruling) or close it as DECIDED
 * on a now-VERIFIED action (the resolution was independently confirmed) — so
 * the state chain admits exactly those gaps, and only after a
 * RESOLVED_EXTERNALLY decision.
 */
function reviewConsistencyErrors(action, decisionItems, reverification) {
  const errors = []
  const review = action.review

  if (review === null) {
    // Not under review: the schema already ties a null review to VERIFIED or a
    // non-terminal status; what it cannot say is that no decision evidence
    // may then exist on the timeline.
    if (decisionItems.length > 0) {
      errors.push(
        consistencyError(
          '/action/review',
          'must be present when the timeline carries a HUMAN_REVIEW_DECISION item',
        ),
      )
    }
    return errors
  }

  const decisions = review.decisions
  if (decisions.length !== decisionItems.length) {
    errors.push(
      consistencyError(
        '/action/review/decisions',
        `must list exactly one decision per HUMAN_REVIEW_DECISION item on the timeline (${decisions.length} vs ${decisionItems.length})`,
      ),
    )
  }
  for (const [index, decision] of decisions.entries()) {
    const item = decisionItems[index]
    if (!item || item.evidenceId !== decision.evidenceId || item.sequence !== decision.evidenceSequence) {
      errors.push(
        consistencyError(
          `/action/review/decisions/${index}/evidenceId`,
          `must name HUMAN_REVIEW_DECISION item ${index} of the timeline, in order` +
            (item ? ` ("${item.evidenceId}" at sequence ${item.sequence})` : ''),
        ),
      )
    }
    if (index > 0 && decisions[index - 1].newReviewState !== decision.previousReviewState) {
      // Format 1.3.0: after a RESOLVED_EXTERNALLY event the Worker's
      // re-verification may have returned the review to PENDING_REVIEW
      // without a decision entry — the only legal gap in the chain.
      const workerReturn =
        reverification &&
        decisions[index - 1].decision === 'RESOLVED_EXTERNALLY' &&
        decision.previousReviewState === 'PENDING_REVIEW'
      if (!workerReturn) {
        errors.push(
          consistencyError(
            `/action/review/decisions/${index}/previousReviewState`,
            `must equal the previous decision's newReviewState (${decisions[index - 1].newReviewState})`,
          ),
        )
      }
    }
  }
  if (decisions.length > 0 && decisions[0].previousReviewState !== 'PENDING_REVIEW') {
    errors.push(
      consistencyError(
        '/action/review/decisions/0/previousReviewState',
        'must be PENDING_REVIEW: every review opens there',
      ),
    )
  }

  const last = decisions.length > 0 ? decisions[decisions.length - 1] : null
  if (JSON.stringify(review.latestDecision) !== JSON.stringify(last)) {
    errors.push(
      consistencyError(
        '/action/review/latestDecision',
        last === null
          ? 'must be null while no decision was recorded'
          : 'must equal the last entry of decisions',
      ),
    )
  }

  const expectedState = last === null ? 'PENDING_REVIEW' : last.newReviewState
  if (action.reviewState !== expectedState) {
    // Format 1.3.0: the Worker's re-verification moves the review after a
    // RESOLVED_EXTERNALLY event without appending a decision — to DECIDED
    // when the now-VERIFIED action's resolution was independently confirmed,
    // or back to PENDING_REVIEW when the new ruling is non-verified.
    const workerMoved =
      reverification &&
      last !== null &&
      last.decision === 'RESOLVED_EXTERNALLY' &&
      ((action.reviewState === 'DECIDED' && action.verificationStatus === 'VERIFIED') ||
        (action.reviewState === 'PENDING_REVIEW' &&
          (action.verificationStatus === 'OUTCOME_MISMATCH' ||
            action.verificationStatus === 'VERIFICATION_FAILED')))
    if (!workerMoved) {
      errors.push(
        consistencyError(
          '/action/reviewState',
          last === null
            ? `must be PENDING_REVIEW while no decision was recorded (got ${action.reviewState})`
            : `must equal the latest decision's newReviewState (${expectedState}, got ${action.reviewState})`,
        ),
      )
    }
  }

  // Format 1.3.0: the independently-confirmed marker and a review carried by
  // a VERIFIED action both exist only through the confirming re-verification
  // of an externally-reported resolution.
  if (reverification) {
    if (action.verificationStatus === 'VERIFIED' && last?.decision !== 'RESOLVED_EXTERNALLY') {
      errors.push(
        consistencyError(
          '/action/review',
          'a VERIFIED action carries a review only when a re-verification confirmed a RESOLVED_EXTERNALLY report — the latest decision must be RESOLVED_EXTERNALLY',
        ),
      )
    }
    if (review.independentlyConfirmed === true && last?.decision !== 'RESOLVED_EXTERNALLY') {
      errors.push(
        consistencyError(
          '/action/review/independentlyConfirmed',
          'true requires the latest decision to be RESOLVED_EXTERNALLY: only a re-verification of an externally-reported resolution can confirm independently',
        ),
      )
    }
  }

  return errors
}

/**
 * Validates one parsed packet document: schema validation against the release
 * matching its declared packetFormatVersion (falling back to the newest
 * supported release when the declaration is missing or unknown, so the
 * version error itself is reported instead of a crash), then the packet-level
 * consistency rules.
 *
 * Returns { valid, version, errors } where errors is an Ajv-shaped list;
 * consistency findings carry keyword "packetConsistency".
 */
export function validatePacket(packet) {
  const declared =
    packet !== null && typeof packet === 'object' && typeof packet.packetFormatVersion === 'string'
      ? packet.packetFormatVersion
      : undefined
  const version = SUPPORTED_VERSIONS.includes(declared) ? declared : SUPPORTED_VERSIONS[0]

  const validate = createValidator(version)
  if (!validate(packet)) {
    return { valid: false, version, errors: validate.errors ?? [] }
  }

  const errors = packetConsistencyErrors(packet, version)
  return { valid: errors.length === 0, version, errors }
}
