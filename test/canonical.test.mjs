// Proves this runtime reproduces the published commitment vectors exactly, and
// refuses everything the specification says must be refused.
//
// These vectors are the agreement point between two independent
// implementations: this one and the .NET implementation inside pruvz-core,
// which vendors this same file and runs the same assertions. A change that
// only one runtime accepts is a broken commitment, and the vectors are how
// that shows up as a failing test instead of an unverifiable packet.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  COMMITMENT_KINDS,
  COMMITMENT_VERSION,
  CommitmentError,
  DIGEST_SUITES,
  REFUSAL_CODES,
  canonicalDecimal,
  canonicalTimestamp,
  canonicalize,
  commitmentDigest,
  commitmentInput,
  evidenceItemDocument,
  evidencePacketDocument,
  requireSupported,
} from '../lib/canonical.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(path.join(here, '..', 'commitment', 'v1', 'golden-vectors.json'), 'utf8'),
)

const documentFor = (kind, source) =>
  kind === 'evidence-item' ? evidenceItemDocument(source) : evidencePacketDocument(source)

/**
 * A vector carries its document either as a parsed value or, where the
 * *spelling* of a number is the point, as raw JSON text: once "5.0" has been
 * parsed into a vector file it is indistinguishable from 5, so those vectors
 * are published as text and each runtime parses them with its own parser.
 */
const documentOf = (vector) =>
  vector.documentJson === undefined ? vector.document : JSON.parse(vector.documentJson)

const refusalCode = (fn) => {
  try {
    fn()
  } catch (error) {
    assert.ok(error instanceof CommitmentError, `expected a CommitmentError, got ${error}`)
    return error.code
  }
  return null
}

test('the vectors declare the format this implementation speaks', () => {
  assert.equal(vectors.commitmentVersion, COMMITMENT_VERSION)
  assert.equal(vectors.digestSuite, DIGEST_SUITES[0])
  assert.deepEqual(vectors.domainSeparation.kinds, COMMITMENT_KINDS)
})

test('every exact decimal normalizes to its published canonical form', () => {
  assert.ok(vectors.decimals.length >= 5)
  for (const vector of vectors.decimals) {
    assert.equal(canonicalDecimal(vector.input), vector.canonical, `decimal "${vector.input}"`)
    // Canonical output is a fixed point: normalizing it again changes nothing.
    assert.equal(canonicalDecimal(vector.canonical), vector.canonical)
  }
})

test('every UTC timestamp normalizes to its published canonical form', () => {
  assert.ok(vectors.timestamps.length >= 3)
  for (const vector of vectors.timestamps) {
    assert.equal(canonicalTimestamp(vector.input), vector.canonical, `timestamp "${vector.input}"`)
    assert.equal(canonicalTimestamp(vector.canonical), vector.canonical)
  }
})

test('every canonicalization vector serializes to its published bytes', () => {
  assert.ok(vectors.canonicalization.length >= 5)
  for (const vector of vectors.canonicalization) {
    assert.equal(
      canonicalize(documentOf(vector)).toString('utf8'),
      vector.canonical,
      `canonicalization vector "${vector.id}"`,
    )
  }
})

test('every commitment vector produces its published canonical bytes and digest', () => {
  assert.ok(vectors.commitments.length >= 3)
  for (const vector of vectors.commitments) {
    const document = documentFor(vector.kind, vector.source)
    assert.equal(
      canonicalize(document).toString('utf8'),
      vector.canonical,
      `commitment vector "${vector.id}"`,
    )
    assert.equal(commitmentDigest(vector.kind, document), vector.digest, `digest "${vector.id}"`)
    assert.match(vector.digest, /^sha256:[0-9a-f]{64}$/)
  }
})

test('every rejected vector is refused with its published code', () => {
  assert.ok(vectors.rejected.length >= 10)
  for (const vector of vectors.rejected) {
    assert.ok(REFUSAL_CODES.includes(vector.code), `unknown refusal code ${vector.code}`)

    const code = refusalCode(() => {
      switch (vector.layer) {
        case 'decimal':
          return canonicalDecimal(vector.input)
        case 'timestamp':
          return canonicalTimestamp(vector.input)
        case 'canonicalization':
          return canonicalize(documentOf(vector))
        case 'commitment':
          return commitmentInput(vector.kind, vector.document)
        case 'digest':
          return commitmentDigest(vector.kind, vector.document, vector.suite)
        case 'evidence-item-document':
          return evidenceItemDocument(vector.source)
        case 'evidence-packet-document':
          return evidencePacketDocument(vector.source)
        case 'supported':
          return requireSupported(vector.commitmentVersion, vector.suite)
        default:
          throw new Error(`unknown vector layer "${vector.layer}"`)
      }
    })

    assert.equal(code, vector.code, `rejected vector "${vector.id}"`)
  }
})

test('the domain-separation header is what the specification says it is', () => {
  const document = { content: {} }
  const input = commitmentInput('evidence-item', document).toString('utf8')
  assert.equal(input, `pruvz.ai/commitment\u0000${COMMITMENT_VERSION}\u0000evidence-item\u0000{"content":{}}`)

  // The same document under two kinds is two different commitments — that is
  // the whole purpose of the header.
  assert.notEqual(
    commitmentDigest('evidence-item', document),
    commitmentDigest('evidence-packet', document),
  )
})

test('a lone surrogate is refused rather than silently replaced', () => {
  // Not a shared vector: a lone surrogate cannot survive a round trip through
  // a JSON vector file in every runtime, so each implementation proves this
  // refusal natively. Encoding it would produce U+FFFD and commit text nobody
  // wrote.
  assert.equal(refusalCode(() => canonicalize({ summary: '\ud800' })), 'LONE_SURROGATE')
  assert.equal(refusalCode(() => canonicalize({ summary: '\udc00 trailing' })), 'LONE_SURROGATE')
  // A well-formed pair is text and commits literally.
  assert.equal(canonicalize({ s: '🧾' }).toString('utf8'), '{"s":"🧾"}')
})

test('a value the canonical model cannot express is refused, never emptied', () => {
  // Not a shared vector either: no JSON file can carry a Date or a class
  // instance. Neither has own enumerable members, so serializing one would
  // produce {} — a commitment over nothing, which is worse than a refusal.
  class Amount {
    constructor(value) {
      this.value = value
    }
  }

  assert.equal(refusalCode(() => canonicalize({ at: new Date(0) })), 'UNSUPPORTED_VALUE')
  assert.equal(refusalCode(() => canonicalize({ amount: new Amount(1) })), 'UNSUPPORTED_VALUE')
  assert.equal(refusalCode(() => canonicalize({ items: new Map() })), 'UNSUPPORTED_VALUE')
  // A plain object — what every JSON parser produces — is the committable case.
  assert.equal(canonicalize({ at: Object.create(null) }).toString('utf8'), '{"at":{}}')
})

test('one logical value has one commitment however it was spelled', () => {
  const spelledOneWay = {
    tenantId: 'tenant-demo',
    packet: {
      packetFormatVersion: '1.4.0',
      action: {
        actionId: 'act_1',
        decision: { amount: { amount: 25, amountExact: '25', currency: 'ILS' } },
        createdAtUtc: '2026-07-10T09:15:41Z',
      },
    },
  }
  const spelledAnother = {
    tenantId: 'tenant-demo',
    packet: {
      packetFormatVersion: '1.4.0',
      action: {
        createdAtUtc: '2026-07-10T09:15:41.000Z',
        decision: { amount: { amount: 25.0, amountExact: '25.00', currency: 'ILS' } },
        actionId: 'act_1',
      },
    },
  }

  assert.equal(
    commitmentDigest('evidence-packet', evidencePacketDocument(spelledOneWay)),
    commitmentDigest('evidence-packet', evidencePacketDocument(spelledAnother)),
  )
})

test('a different value is a different commitment', () => {
  const base = {
    tenantId: 'tenant-demo',
    packet: {
      packetFormatVersion: '1.4.0',
      action: {
        actionId: 'act_1',
        decision: { amount: { amount: 25, amountExact: '25', currency: 'ILS' } },
      },
    },
  }
  const digest = commitmentDigest('evidence-packet', evidencePacketDocument(base))

  const changes = [
    (p) => {
      p.action.decision.amount.amountExact = '25.01'
    },
    (p) => {
      p.action.decision.amount.currency = 'USD'
    },
    (p) => {
      p.action.actionId = 'act_2'
    },
    (p) => {
      p.packetFormatVersion = '1.3.0'
    },
  ]

  for (const change of changes) {
    const mutated = JSON.parse(JSON.stringify(base))
    change(mutated.packet)
    assert.notEqual(commitmentDigest('evidence-packet', evidencePacketDocument(mutated)), digest)
  }

  // The trust domain is committed too: the same packet under another tenant is
  // another commitment.
  assert.notEqual(
    commitmentDigest('evidence-packet', evidencePacketDocument({ ...base, tenantId: 'tenant-other' })),
    digest,
  )
})

test('the JSON number beside an exact amount never reaches the commitment', () => {
  const withHonestNumber = {
    tenantId: 'tenant-demo',
    packet: {
      packetFormatVersion: '1.4.0',
      action: {
        actionId: 'act_1',
        decision: { amount: { amount: 25, amountExact: '25', currency: 'ILS' } },
      },
    },
  }
  const withLyingNumber = JSON.parse(JSON.stringify(withHonestNumber))
  withLyingNumber.packet.action.decision.amount.amount = 9999.99

  // Identical commitments — which is exactly why the packet validator must
  // reject the disagreement itself (see the disagreeing-exact-amount example).
  assert.equal(
    commitmentDigest('evidence-packet', evidencePacketDocument(withLyingNumber)),
    commitmentDigest('evidence-packet', evidencePacketDocument(withHonestNumber)),
  )
})

test('every published example packet can be committed', () => {
  // The commitment must cover real exported packets, not only vector-shaped
  // documents: any money value or timestamp the contract can express has to
  // normalize, or the packet would be unverifiable in practice.
  const validDir = path.join(here, '..', 'examples', 'valid')

  for (const file of ['verified-refund', 'outcome-mismatch-decided', 'reverified-confirmed']) {
    const packet = JSON.parse(
      readFileSync(path.join(validDir, `${file}.packet.json`), 'utf8'),
    )
    const digest = commitmentDigest(
      'evidence-packet',
      evidencePacketDocument({ tenantId: 'tenant-demo', packet }),
    )
    assert.match(digest, /^sha256:[0-9a-f]{64}$/, `${file} must commit`)
  }
})
