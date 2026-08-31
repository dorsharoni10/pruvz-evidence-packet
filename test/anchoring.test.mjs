// Proves this runtime reproduces the published anchoring vectors exactly,
// accepts everything the specification says must be accepted, and refuses
// everything it says must be refused — with the same reason code.
//
// These vectors are the agreement point between two independent
// implementations: this one and the .NET implementation inside pruvz-core,
// which vendors this same file and runs the same case tables. An anchor one
// runtime accepts and the other refuses is a broken anchor, and the vectors
// are how that shows up as a failing test instead of as a dispute over whether
// a history was ever witnessed.
//
// What these tests do NOT establish is the whole point of the file's honesty:
// nothing here proves a token is genuine. Half two of docs/ANCHORING.md — the
// signature, the timestamping extended key usage, the certificate's validity
// at genTime, the chain to a pinned root and the policy — belongs to a
// platform CMS and X.509 implementation, and one published vector
// (checkpoint-token-signature-corrupted) exists to make that boundary
// impossible to overlook.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  ANCHORING_FORMAT_VERSION,
  ANCHOR_STATUSES,
  AnchorError,
  BLINDING_NONCE_BYTES,
  REFUSAL_CODES,
  SUBJECT_DOMAIN_TAGS,
  SUBJECT_KINDS,
  anchorImprint,
  anchorInput,
  newBlindingNonce,
  newRequestNonce,
  readTimestampToken,
  subjectMaterial,
  validateAnchorRecord,
  verifyAnchorBinding,
} from '../lib/anchoring.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(path.join(here, '..', 'anchoring', 'v1', 'golden-vectors.json'), 'utf8'),
)

/** A receipt token beginning with "@" names an entry in `receipts`. */
const resolveToken = (token) =>
  token.startsWith('@') ? vectors.receipts[token.slice(1)] : token

const materialize = (record) =>
  record.receipt === null || record.receipt === undefined
    ? record
    : { ...record, receipt: { ...record.receipt, token: resolveToken(record.receipt.token) } }

const subjectOf = (ref) => vectors.subjects[ref]

const refuses = (code, run) => {
  assert.throws(run, (error) => {
    assert.ok(error instanceof AnchorError, `expected an AnchorError, got ${error}`)
    assert.equal(error.code, code)
    return true
  })
}

test('the vectors describe the version and the domains this implementation speaks', () => {
  assert.equal(vectors.anchoringFormatVersion, ANCHORING_FORMAT_VERSION)
  assert.equal(vectors.domainSeparation.logCheckpoint.tag, SUBJECT_DOMAIN_TAGS['log-checkpoint'])
  assert.equal(vectors.domainSeparation.trustRegistry.tag, SUBJECT_DOMAIN_TAGS['trust-registry'])
  assert.deepEqual(SUBJECT_KINDS, ['log-checkpoint', 'trust-registry'])
  assert.equal(vectors.hashing.blindingNonceBytes, BLINDING_NONCE_BYTES)
})

test('the deterministic layer reproduces byte for byte', () => {
  assert.ok(vectors.deterministic.length > 0)
  for (const entry of vectors.deterministic) {
    const subject = subjectOf(entry.subjectRef)
    const kind = entry.subjectRef.startsWith('trust-registry') ? 'trust-registry' : 'log-checkpoint'
    const input = anchorInput(kind, entry.blindingNonce, subject)

    assert.equal(input.length, entry.anchorInputLength, `${entry.id}: anchorInput length`)
    assert.equal(
      createHash('sha256').update(input).digest('hex'),
      entry.anchorInputSha256,
      `${entry.id}: anchorInput digest`,
    )
    assert.equal(
      anchorImprint(kind, entry.blindingNonce, subject).toString('hex'),
      entry.imprint,
      `${entry.id}: imprint`,
    )
  }
})

test('the imprint begins with the domain tag, the version and the raw nonce', () => {
  const entry = vectors.deterministic[0]
  const nonce = Buffer.from(entry.blindingNonce, 'base64url')
  const input = anchorInput('log-checkpoint', nonce, subjectOf(entry.subjectRef))

  const NUL = String.fromCharCode(0)
  const header = Buffer.from(
    `${SUBJECT_DOMAIN_TAGS['log-checkpoint']}${NUL}${ANCHORING_FORMAT_VERSION}${NUL}`,
    'utf8',
  )
  assert.ok(input.subarray(0, header.length).equals(header))
  // The nonce follows as 32 RAW bytes, with no separator — its width is what
  // makes that unambiguous.
  assert.ok(input.subarray(header.length, header.length + BLINDING_NONCE_BYTES).equals(nonce))
})

test('the two domain tags are not interchangeable', () => {
  // One subject cannot be anchored under the other kind at all — the subject
  // shapes differ — so the separation is proven where it is observable: the
  // header bytes differ, and no imprint from one domain can equal one from the
  // other for the same nonce.
  const nonce = Buffer.alloc(BLINDING_NONCE_BYTES, 5)
  const checkpointInput = anchorInput('log-checkpoint', nonce, subjectOf('log-checkpoint'))
  const registryInput = anchorInput('trust-registry', nonce, subjectOf('trust-registry'))

  assert.ok(checkpointInput.includes(Buffer.from('pruvz.ai/log-anchor')))
  assert.ok(registryInput.includes(Buffer.from('pruvz.ai/trust-registry-anchor')))
  assert.notEqual(
    createHash('sha256').update(checkpointInput).digest('hex'),
    createHash('sha256').update(registryInput).digest('hex'),
  )
})

test('one subject under two blinding nonces gives unrelated imprints', () => {
  // This is the property the nonce exists for: an observer holding an imprint
  // cannot recompute it from a candidate subject without also holding the
  // nonce, which never leaves the deployment.
  const subject = subjectOf('log-checkpoint')
  const a = anchorImprint('log-checkpoint', Buffer.alloc(32, 1), subject).toString('hex')
  const b = anchorImprint('log-checkpoint', Buffer.alloc(32, 2), subject).toString('hex')
  assert.notEqual(a, b)
})

test('a trust-registry subject drops attestations, so a witness can be added later', () => {
  // The receipt lands in attestations; a subject that included them could never
  // be witnessed. Checking the pair and the whole document must therefore give
  // one imprint.
  const pair = subjectMaterial('trust-registry', subjectOf('trust-registry'))
  const whole = subjectMaterial('trust-registry', subjectOf('trust-registry-whole-document'))
  assert.deepEqual(Object.keys(whole.document).sort(), ['manifest', 'signatures'])
  assert.deepEqual(pair.document, whole.document)

  const nonce = Buffer.alloc(32, 9)
  assert.equal(
    anchorImprint('trust-registry', nonce, subjectOf('trust-registry')).toString('hex'),
    anchorImprint('trust-registry', nonce, subjectOf('trust-registry-whole-document')).toString('hex'),
  )
})

test('every published binding case behaves as published', () => {
  assert.ok(vectors.bindingCases.length > 0)
  for (const item of vectors.bindingCases) {
    const result = verifyAnchorBinding({
      record: materialize(item.record),
      subject: subjectOf(item.subjectRef),
    })
    for (const [member, expected] of Object.entries(item.expect)) {
      assert.equal(result[member], expected, `${item.id}: ${member}`)
    }
  }
})

test('a checked binding never claims the authority was verified', () => {
  // Stated in the result itself so a caller cannot pass the object on as
  // though trust had been established.
  for (const item of vectors.bindingCases) {
    const result = verifyAnchorBinding({
      record: materialize(item.record),
      subject: subjectOf(item.subjectRef),
    })
    assert.equal(result.authorityVerified, false, `${item.id}`)
  }
})

test('the published divergence: a corrupted signature binds here and must not elsewhere', () => {
  // This case is deliberately NOT in bindingCases. Those are the agreement
  // points; this is the one place two conformant implementations must differ,
  // and publishing it as agreement would be a false claim about what half one
  // establishes.
  assert.equal(vectors.runtimeDivergence.length, 1)
  const item = vectors.runtimeDivergence[0]
  assert.ok(
    !vectors.bindingCases.some((c) => c.id === item.id),
    'the divergence case must not also be published as agreement',
  )

  const corrupted = resolveToken('@checkpoint-signature-corrupted')
  assert.notEqual(
    corrupted,
    resolveToken('@checkpoint'),
    'the case must actually differ from the genuine token',
  )

  // It parses, it binds, and this implementation accepts it — which is exactly
  // why this implementation is not a verifier. A runtime that performs half
  // two must refuse the same bytes.
  const result = verifyAnchorBinding({
    record: materialize(item.record),
    subject: subjectOf(item.subjectRef),
  })
  assert.equal(item.halfOne.accepts, true)
  assert.equal(result.imprint, item.halfOne.imprint)
  assert.equal(result.genTime, item.halfOne.genTime)
  assert.equal(result.authorityVerified, false)

  assert.equal(item.halfTwo.accepts, false)
  assert.ok(REFUSAL_CODES.includes(item.halfTwo.expect))
  for (const code of item.halfTwo.alsoAcceptable) {
    assert.ok(REFUSAL_CODES.includes(code))
  }
})

test('every published refusal is refused with the published code', () => {
  assert.ok(vectors.refusals.length > 0)
  for (const item of vectors.refusals) {
    assert.ok(REFUSAL_CODES.includes(item.expect), `${item.id}: ${item.expect} is not a refusal code`)
    refuses(item.expect, () =>
      verifyAnchorBinding({
        record: materialize(item.record),
        subject: subjectOf(item.subjectRef),
      }),
    )
  }
})

test('every refusal code this implementation can produce is exercised', () => {
  // The two half-two codes are part of the vocabulary and cannot be produced
  // here: an implementation that validates the authority produces them.
  const halfTwo = ['ANCHOR_SIGNATURE_INVALID', 'ANCHOR_UNTRUSTED_AUTHORITY']
  const covered = new Set(vectors.refusals.map((item) => item.expect))
  for (const code of REFUSAL_CODES) {
    if (halfTwo.includes(code)) {
      assert.ok(!covered.has(code), `${code} cannot be produced by this implementation`)
      continue
    }
    assert.ok(covered.has(code), `${code} has no vector`)
  }
})

test('a real token is read the way the authority reported it', () => {
  const token = readTimestampToken(resolveToken('@checkpoint'))
  const expected = vectors.bindingCases.find((c) => c.id === 'checkpoint-anchored').expect

  assert.equal(token.genTime, expected.genTime)
  assert.equal(token.policyOid, expected.policyOid)
  assert.equal(token.messageImprint.algorithm, 'sha-256')
  assert.equal(token.messageImprint.hash.toString('hex'), expected.imprint)
  assert.ok(token.nonce !== null && token.nonce.length >= 8)
})

test('an unsupported imprint suite is read but refused', () => {
  // The token is real and well-formed; the refusal is about the suite, and the
  // reader still reports what it is rather than pretending not to know.
  const token = readTimestampToken(resolveToken('@sha512-imprint'))
  assert.equal(token.messageImprint.algorithm, null)
  assert.equal(token.messageImprint.algorithmOid, '2.16.840.1.101.3.4.2.3')
  assert.equal(token.messageImprint.hash.length, 64)
})

test('a nonce is compared by unsigned value, not by encoding', () => {
  // DER prepends 0x00 to an INTEGER whose high bit is set, so the same nonce
  // can be 8 bytes in one encoding and 9 in another. A record whose nonce
  // carries a redundant leading zero must still match.
  const item = vectors.bindingCases.find((c) => c.id === 'checkpoint-anchored')
  const nonce = Buffer.from(item.record.requestNonce, 'base64url')
  const padded = Buffer.concat([Buffer.alloc(1), nonce])

  const result = verifyAnchorBinding({
    record: materialize({ ...item.record, requestNonce: padded.toString('base64url') }),
    subject: subjectOf(item.subjectRef),
  })
  assert.equal(result.genTime, item.expect.genTime)
})

test('record validation refuses before it reads, and returns the decoded nonces', () => {
  const item = vectors.bindingCases.find((c) => c.id === 'checkpoint-anchored')
  const record = materialize(item.record)
  const { blindingNonce, requestNonce } = validateAnchorRecord(record)

  assert.equal(blindingNonce.length, BLINDING_NONCE_BYTES)
  assert.ok(requestNonce.length >= 8)
  // An unknown version is refused before the member set is examined: a record
  // that is both a wrong version and structurally broken reports the version.
  refuses('UNKNOWN_ANCHOR_VERSION', () => validateAnchorRecord({ version: '2', nonsense: true }))
  refuses('UNKNOWN_ANCHOR_VERSION', () => validateAnchorRecord({}))
  refuses('ANCHOR_MALFORMED', () => validateAnchorRecord(null))
})

test('the generated nonces are the widths the format requires', () => {
  assert.equal(newBlindingNonce().length, BLINDING_NONCE_BYTES)
  assert.notEqual(newBlindingNonce().toString('hex'), newBlindingNonce().toString('hex'))

  const requestNonce = newRequestNonce()
  assert.ok(requestNonce.length >= 8)
  // The high bit is cleared so the value is unambiguously positive as a DER
  // INTEGER and its minimal unsigned encoding is the bytes themselves.
  assert.ok(requestNonce[0] < 0x80 && requestNonce[0] !== 0)
  refuses('ANCHOR_MALFORMED', () => newRequestNonce(4))
})

test('the status set is closed and receipt presence follows it', () => {
  assert.deepEqual(ANCHOR_STATUSES, ['ANCHORED', 'PENDING', 'FAILED'])
  const item = vectors.bindingCases.find((c) => c.id === 'checkpoint-anchored')
  for (const status of ['PENDING', 'FAILED']) {
    // Not anchored is not "anchored a bit": it is the ANCHOR_NOT_PRESENT path,
    // and no verdict on this path may be a full one.
    refuses('ANCHOR_NOT_PRESENT', () =>
      verifyAnchorBinding({
        record: materialize({ ...item.record, status, receipt: null }),
        subject: subjectOf(item.subjectRef),
      }),
    )
  }
})
