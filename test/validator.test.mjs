// Proves the published samples and the validator behave exactly as documented:
// every valid example conforms, every invalid example is rejected — and
// rejected for its one documented defect, not for an accident elsewhere.
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { SUPPORTED_VERSIONS, createValidator, validatePacket } from '../lib/validator.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.join(here, '..')
const validDir = path.join(repoRoot, 'examples', 'valid')
const capturedDir = path.join(repoRoot, 'examples', 'captured')
const invalidDir = path.join(repoRoot, 'examples', 'invalid')

const loadPacket = (dir, name) => JSON.parse(readFileSync(path.join(dir, name), 'utf8'))
const packetFiles = (dir) => readdirSync(dir).filter((f) => f.endsWith('.packet.json'))

// Each invalid example must fail because of its one documented defect. The
// pattern matches the Ajv error list (paths + messages) for that defect.
const invalidExpectations = {
  'wrong-trust-level.packet.json': /trustLevel/,
  'fabricated-final-outcome.packet.json': /finalOutcome/,
  'missing-policy-snapshot.packet.json': /policySnapshot/,
  'negative-amount.packet.json': /decision\/amount\/amount.*>= 0/,
  'undeclared-content-hash.packet.json': /additional properties/,
  'malformed-timestamp.packet.json': /createdAtUtc.*(format|pattern)/,
  'offset-timestamp.packet.json': /updatedAtUtc.*pattern/,
  'mismatch-without-dimensions.packet.json': /\/action\/mismatch/,
  'fabricated-zero-discrepancy.packet.json': /businessDiscrepancy\/amount/,
  'unsupported-format-version.packet.json': /packetFormatVersion/,
  'independently-confirmed-not-verified.packet.json': /independentlyConfirmed/,
  'disagreeing-exact-amount.packet.json': /amountExact.*must denote the same amount/,
}

/**
 * Strips everything format 1.4.0 added, so a packet can be re-read as an
 * earlier release whose strict schema rejects undeclared fields.
 */
const withoutExactAmounts = (value) => {
  if (Array.isArray(value)) {
    return value.map(withoutExactAmounts)
  }
  if (value === null || typeof value !== 'object') {
    return value
  }
  const out = {}
  for (const [key, member] of Object.entries(value)) {
    if (key === 'amountExact' && typeof value.currency === 'string') {
      continue
    }
    out[key] = withoutExactAmounts(member)
  }
  return out
}

/**
 * Strips what format 1.5.0 added to timeline items — the four fields the
 * canonical evidence-item commitment binds (runId, schemaVersion,
 * clientOperationId, payloadMetadata) — so a test can derive an older-format
 * packet from a current example.
 */
const withoutCommitmentFields = (packet) => {
  const out = JSON.parse(JSON.stringify(packet))
  for (const item of out.evidence?.items ?? []) {
    delete item.runId
    delete item.schemaVersion
    delete item.clientOperationId
    delete item.payloadMetadata
  }
  return out
}

test('every valid example conforms to the published schema', () => {
  const files = packetFiles(validDir)
  assert.ok(files.length >= 5, 'expected at least five valid examples')

  for (const file of files) {
    const { valid, errors } = validatePacket(loadPacket(validDir, file))
    assert.ok(valid, `${file} should be valid but failed: ${JSON.stringify(errors, null, 2)}`)
  }
})

test('the packet captured from a real product run conforms', () => {
  // The conformance proof (docs/CONFORMANCE.md): real product output,
  // composed with bin/compose.mjs, must pass the same two-layer validation
  // as every authored example.
  const files = packetFiles(capturedDir)
  assert.ok(files.length >= 1, 'expected at least one captured packet')

  for (const file of files) {
    const { valid, errors } = validatePacket(loadPacket(capturedDir, file))
    assert.ok(valid, `${file} should be valid but failed: ${JSON.stringify(errors, null, 2)}`)
  }
})

test('every invalid example is rejected for its documented defect', () => {
  const files = packetFiles(invalidDir)
  assert.deepEqual(
    files.sort(),
    Object.keys(invalidExpectations).sort(),
    'examples/invalid and the test manifest must list exactly the same files',
  )

  for (const file of files) {
    const { valid, errors } = validatePacket(loadPacket(invalidDir, file))
    assert.equal(valid, false, `${file} should fail structural validation`)

    const rendered = errors
      .map((error) => `${error.instancePath} ${error.message}`)
      .join('\n')
    assert.match(
      rendered,
      invalidExpectations[file],
      `${file} failed, but not for its documented defect. Errors:\n${rendered}`,
    )
  }
})

// Packet-level consistency: cross-object rules JSON Schema cannot express.
// Each scenario mutates a schema-valid example in memory and must be rejected
// by the consistency layer with an error at the expected location.
const consistencyScenarios = [
  {
    name: 'action.actionId differing from evidence.actionId',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      p.evidence.actionId = 'act_someoneelsesaction00000000000001'
    },
    expect: /\/evidence\/actionId.*must equal/,
  },
  {
    name: 'two evidence items with the same sequence',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      p.evidence.items[3].sequence = 3
    },
    expect: /\/evidence\/items\/3\/sequence/,
  },
  {
    name: 'a gap in the timeline sequences',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      p.evidence.items[5].sequence = 9
    },
    expect: /\/evidence\/items\/5\/sequence/,
  },
  {
    name: 'a timeline reported out of sequence order',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      const [first] = p.evidence.items.splice(0, 1)
      p.evidence.items.push(first)
    },
    expect: /sequence/,
  },
  {
    name: 'a duplicated evidenceId',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      p.evidence.items[1].evidenceId = p.evidence.items[0].evidenceId
    },
    expect: /evidenceId.*must be unique/,
  },
  {
    name: 'a review history without its HUMAN_REVIEW_DECISION evidence (format 1.2.0)',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.evidence.items = p.evidence.items.filter((i) => i.type !== 'HUMAN_REVIEW_DECISION')
    },
    expect: /review\/decisions.*exactly one decision per HUMAN_REVIEW_DECISION/,
  },
  {
    name: 'a review state that disagrees with the latest decision (format 1.2.0)',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.action.reviewState = 'PENDING_REVIEW'
    },
    expect: /reviewState.*must equal the latest decision's newReviewState \(DECIDED/,
  },
  {
    name: 'a latestDecision that is not the last entry of decisions (format 1.2.0)',
    base: 'verification-failed-resolved-externally.packet.json',
    mutate: (p) => {
      p.action.review.latestDecision = p.action.review.decisions[0]
      p.action.reviewState = 'NEEDS_CORRECTION'
    },
    expect: /latestDecision.*must equal the last entry of decisions/,
  },
  {
    name: 'a decision history out of timeline order (format 1.2.0)',
    base: 'verification-failed-resolved-externally.packet.json',
    mutate: (p) => {
      p.action.review.decisions.reverse()
      p.action.review.latestDecision = p.action.review.decisions[1]
      p.action.reviewState = 'NEEDS_CORRECTION'
    },
    expect: /review\/decisions\/0\/evidenceId.*in order/,
  },
  {
    name: 'decision evidence on an action that is not under review (format 1.2.0)',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.action.verificationStatus = 'VERIFIED'
      p.action.finalOutcome = 'REFUND_SUCCEEDED'
      p.action.mismatch = null
      p.action.reviewState = 'NOT_REQUIRED'
      p.action.review = null
    },
    expect: /\/action\/review.*must be present when the timeline carries a HUMAN_REVIEW_DECISION/,
  },
  {
    name: 'a pending review that already carries a decision (format 1.2.0)',
    base: 'verification-failed.packet.json',
    mutate: (p) => {
      p.action.reviewState = 'DECIDED'
    },
    expect: /reviewState.*must be PENDING_REVIEW while no decision was recorded/,
  },
  {
    name: 'VERIFIED while execution is still RECEIVED',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      p.action.executionStatus = 'RECEIVED'
      p.action.executionStartedAtUtc = null
      p.action.executionCompletedAtUtc = null
    },
    expect: /verificationStatus.*requires executionStatus COMPLETED/,
  },
  {
    name: 'an executionCompletedAtUtc timestamp while still EXECUTING',
    base: 'verification-pending.packet.json',
    mutate: (p) => {
      p.action.executionStatus = 'EXECUTING'
      p.action.verificationStatus = 'NOT_STARTED'
    },
    expect: /executionCompletedAtUtc.*must be null/,
  },
  {
    name: 'an absent-after-deadline mismatch without a resolved deadline (format 1.1.0)',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.action.verificationTiming.deadlineAtUtc = null
      p.action.verificationTiming.deadlineSource = 'NOT_CONFIGURED'
    },
    expect: /mismatchReason.*requires a resolved verificationTiming/,
  },
  {
    name: 'a Worker return to PENDING_REVIEW without a RESOLVED_EXTERNALLY decision (format 1.3.0)',
    base: 'reverified-mismatch.packet.json',
    mutate: (p) => {
      p.action.review.decisions[0].decision = 'NEEDS_CORRECTION'
      p.action.review.latestDecision.decision = 'NEEDS_CORRECTION'
    },
    expect: /reviewState.*must equal the latest decision's newReviewState/,
  },
  {
    name: 'follow-up read-back evidence without a recorded fresh window (format 1.3.0)',
    base: 'reverified-mismatch.packet.json',
    mutate: (p) => {
      p.action.reverificationTiming = null
    },
    expect: /reverificationTiming.*requires the fresh re-verification window/,
  },
  {
    name: 'a recorded re-verification window without a RESOLVED_EXTERNALLY report (format 1.3.0)',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      // The review history holds only APPROVED_EXCEPTION — no reported
      // external correction ever opened a fresh window, so a recorded one is
      // fabricated.
      p.action.reverificationTiming = { ...p.action.verificationTiming }
    },
    expect: /reverificationTiming.*requires a RESOLVED_EXTERNALLY decision/,
  },
  {
    name: 'a money value deeper in the record whose two representations disagree (format 1.4.0)',
    base: 'verified-refund.packet.json',
    mutate: (p) => {
      // Not the headline decision amount this time: the rule has to bind every
      // money value in the record, including the Policy Snapshot's limits.
      p.action.policySnapshot.rules.maxRefundAmount.amountExact = '1000'
    },
    expect: /policySnapshot\/rules\/maxRefundAmount\/amountExact.*must denote the same amount/,
  },
  {
    name: 'a VERIFIED review closed by a human disposition instead of a re-verification (format 1.3.0)',
    base: 'reverified-confirmed.packet.json',
    mutate: (p) => {
      const last = p.action.review.decisions[1]
      last.decision = 'DISMISSED'
      last.newReviewState = 'DECIDED'
      p.action.review.latestDecision = last
    },
    expect: /latest decision must be RESOLVED_EXTERNALLY/,
  },
]

test('self-contradictory packets are rejected by the consistency layer', () => {
  for (const scenario of consistencyScenarios) {
    const packet = loadPacket(validDir, scenario.base)
    scenario.mutate(packet)
    // Mutations must not accidentally break schema validity elsewhere — clean
    // up any accidental undefined left by a mutation.
    const cleaned = JSON.parse(JSON.stringify(packet))

    const { valid, errors } = validatePacket(cleaned)
    assert.equal(valid, false, `"${scenario.name}" must be rejected`)

    const rendered = errors
      .map((error) => `${error.instancePath} ${error.message}`)
      .join('\n')
    assert.match(
      rendered,
      scenario.expect,
      `"${scenario.name}" was rejected, but not for the expected reason. Errors:\n${rendered}`,
    )
  }
})

test('the exact amount admits every value an exact decimal type can hold', () => {
  // The contract must be able to express any amount a producer can produce: a
  // rule narrower than the product's decimal type — in the grammar or in the
  // consistency layer — would turn a legal amount into an unexportable packet.
  //
  // The middle case is the one that matters: it is larger than a double can
  // hold exactly but still prints as plain decimal text, so a rule that
  // compared printed forms would reject it. The number is the nearest double
  // to the exact amount, which is all a JSON number can ever be, and the
  // string carries the value.
  const extremes = [
    ['79228162514264337593543950335', 7.922816251426434e28],
    ['100000000000000001', 100000000000000000],
    ['0.0000000000000000000000000001', 1e-28],
  ]

  for (const [amountExact, amount] of extremes) {
    const packet = loadPacket(validDir, 'verified-refund.packet.json')
    packet.action.decision.amount = { amount, amountExact, currency: 'USD' }

    const { valid, errors } = validatePacket(packet)
    assert.ok(valid, `${amountExact} should be expressible: ${JSON.stringify(errors, null, 2)}`)
  }
})

test('a legacy record without verification timing keeps its historical mismatch valid', () => {
  // The schema admits verificationTiming: null exactly for action records
  // that predate the timing model — and such records may carry historical
  // absent-after-deadline mismatches without a recorded resolution. The
  // deadline consistency rule must bind only records the timing model covers,
  // or the contract would reject input it explicitly declares legal.
  const packet = loadPacket(validDir, 'outcome-mismatch-decided.packet.json')
  packet.action.verificationTiming = null

  const { valid, errors } = validatePacket(packet)
  assert.ok(
    valid,
    `a legacy no-timing mismatch packet should be valid but failed: ${JSON.stringify(errors, null, 2)}`,
  )
})

test('formats before 1.3.0 keep the strict review-state chain (no Worker transitions)', () => {
  // The Worker's re-verification return transitions exist only from format
  // 1.3.0. A 1.2.0 packet claiming the same shape — PENDING_REVIEW while the
  // latest decision moved the review to AWAITING_REVERIFICATION — must still
  // be rejected by the 1.2.0 consistency rules. Derived from the 1.3.0
  // re-mismatch example by removing everything 1.3.0 added.
  const packet = withoutCommitmentFields(
    withoutExactAmounts(loadPacket(validDir, 'reverified-mismatch.packet.json')),
  )
  packet.packetFormatVersion = '1.2.0'
  delete packet.action.reverificationTiming
  delete packet.action.review.independentlyConfirmed
  packet.evidence.items = packet.evidence.items.filter(
    (item) => item.type !== 'FOLLOW_UP_INDEPENDENT_READBACK',
  )
  packet.evidence.items[packet.evidence.items.length - 1].sequence = 8

  const { valid, errors } = validatePacket(packet)
  assert.equal(valid, false, 'the derived 1.2.0 packet must be rejected')
  assert.match(
    errors.map((e) => `${e.instancePath} ${e.message}`).join('\n'),
    /reviewState.*must equal the latest decision's newReviewState/,
  )
})

test('formats before 1.2.0 keep the DECIDED-implies-decision-evidence rule', () => {
  // A 1.1.0 packet has no review block; its only review rule couples DECIDED
  // with HUMAN_REVIEW_DECISION evidence both ways. Derived from the 1.2.0
  // decided example by removing what 1.2.0 added.
  const packet = withoutCommitmentFields(
    withoutExactAmounts(loadPacket(validDir, 'outcome-mismatch-decided.packet.json')),
  )
  packet.packetFormatVersion = '1.1.0'
  delete packet.action.review
  delete packet.action.reverificationTiming

  assert.ok(validatePacket(packet).valid, 'the derived 1.1.0 packet should be valid')

  const undecided = JSON.parse(JSON.stringify(packet))
  undecided.action.reviewState = 'PENDING_REVIEW'
  const { valid, errors } = validatePacket(undecided)
  assert.equal(valid, false)
  assert.match(
    errors.map((e) => `${e.instancePath} ${e.message}`).join('\n'),
    /reviewState.*must be DECIDED/,
  )
})

test('valid and invalid examples stay internally consistent on actionId', () => {
  // Belt and braces: the consistency layer now enforces this at validation
  // time; this keeps the published examples honest even if that layer changes.
  for (const file of packetFiles(validDir)) {
    const packet = loadPacket(validDir, file)
    assert.equal(
      packet.action.actionId,
      packet.evidence.actionId,
      `${file}: action.actionId must equal evidence.actionId`,
    )
  }
})

test('an unsupported explicit version is refused, not silently accepted', () => {
  assert.throws(() => createValidator('2.0.0'), /Unsupported packet format version/)
  assert.deepEqual(SUPPORTED_VERSIONS, ['1.5.0', '1.4.0', '1.3.0', '1.2.0', '1.1.0', '1.0.0'])
})

test('the documented CLI command validates without any network access', () => {
  const cli = path.join(repoRoot, 'bin', 'validate.mjs')
  const validFile = path.join(validDir, 'verified-refund.packet.json')
  const invalidFile = path.join(invalidDir, 'wrong-trust-level.packet.json')

  const pass = spawnSync(process.execPath, [cli, validFile], { encoding: 'utf8' })
  assert.equal(pass.status, 0, `expected exit 0, got ${pass.status}: ${pass.stderr}`)
  assert.match(pass.stdout, /PASS/)

  const fail = spawnSync(process.execPath, [cli, validFile, invalidFile], { encoding: 'utf8' })
  assert.equal(fail.status, 1, 'one nonconforming file must fail the whole run')
  assert.match(fail.stderr, /FAIL/)
})
