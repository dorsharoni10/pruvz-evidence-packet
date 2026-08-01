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
}

test('every valid example conforms to the published schema', () => {
  const files = packetFiles(validDir)
  assert.ok(files.length >= 4, 'expected at least four valid examples')

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
    name: 'reviewState DECIDED without HUMAN_REVIEW_DECISION evidence',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.evidence.items = p.evidence.items.filter((i) => i.type !== 'HUMAN_REVIEW_DECISION')
    },
    expect: /reviewState.*DECIDED requires a HUMAN_REVIEW_DECISION/,
  },
  {
    name: 'HUMAN_REVIEW_DECISION evidence while still PENDING_REVIEW',
    base: 'outcome-mismatch-decided.packet.json',
    mutate: (p) => {
      p.action.reviewState = 'PENDING_REVIEW'
    },
    expect: /reviewState.*must be DECIDED/,
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
  assert.deepEqual(SUPPORTED_VERSIONS, ['1.0.0'])
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
