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

const here = path.dirname(fileURLToPath(import.meta.url))
const schemaRoot = path.join(here, '..', 'schema')

/** Packet format versions this checkout can validate, newest first. */
export const SUPPORTED_VERSIONS = ['1.0.0']

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
 * The cross-object rules of the packet format, checked only after the packet
 * is schema-valid (they assume the declared structure). Returns Ajv-shaped
 * error objects so the two layers report uniformly.
 */
export function packetConsistencyErrors(packet) {
  const errors = []
  const { action, evidence } = packet
  const items = evidence.items

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

  // A recorded human decision and the DECIDED review state imply each other:
  // the decision is appended as HUMAN_REVIEW_DECISION evidence in the same
  // consistency boundary that flips the review state.
  const hasDecisionEvidence = items.some((item) => item.type === 'HUMAN_REVIEW_DECISION')
  if (action.reviewState === 'DECIDED' && !hasDecisionEvidence) {
    errors.push(
      consistencyError(
        '/action/reviewState',
        'DECIDED requires a HUMAN_REVIEW_DECISION item on the evidence timeline',
      ),
    )
  }
  if (hasDecisionEvidence && action.reviewState !== 'DECIDED') {
    errors.push(
      consistencyError(
        '/action/reviewState',
        `must be DECIDED when the timeline carries a HUMAN_REVIEW_DECISION item (got ${action.reviewState})`,
      ),
    )
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

  const errors = packetConsistencyErrors(packet)
  return { valid: errors.length === 0, version, errors }
}
