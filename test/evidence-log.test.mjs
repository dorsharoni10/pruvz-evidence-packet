// Proves this runtime reproduces the published evidence-log vectors exactly,
// accepts everything the specification says must be accepted, and refuses
// everything it says must be refused — with the same reason code.
//
// These vectors are the agreement point between two independent
// implementations: this one and the .NET implementation inside pruvz-core,
// which vendors this same file and runs the same case tables. A history one
// runtime accepts and the other refuses is a broken log, and the vectors are
// how that shows up as a failing test instead of as a dispute over whether a
// record was ever there.
import assert from 'node:assert/strict'
import { createHash, createPublicKey, verify as verifyEcdsa } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { sealSigningInput } from '../lib/trust-registry.mjs'
import {
  ASSURANCE_PROFILES,
  CHECKPOINT_DOMAIN_TAG,
  EVIDENCE_LOG_FORMAT_VERSION,
  EvidenceLogError,
  LEAF_DOMAIN_TAG,
  LEAF_ENVELOPE_VERSION,
  LEAF_HASH_PREFIX,
  NODE_HASH_PREFIX,
  REFUSAL_CODES,
  acceptCheckpoint,
  checkpointSigningInput,
  consistencyProof,
  emptyTreeHash,
  inclusionPath,
  leafHashOf,
  leafInput,
  requireSupported,
  rootHashText,
  sealLeafHash,
  treeHead,
  validateCheckpointDocument,
  verifyCheckpoint,
  verifyConsistency,
  verifyInclusion,
} from '../lib/evidence-log.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(path.join(here, '..', 'evidence-log', 'v1', 'golden-vectors.json'), 'utf8'),
)

const sha256hex = (buffer) => createHash('sha256').update(buffer).digest('hex')

const refusalCode = (fn) => {
  try {
    fn()
  } catch (error) {
    assert.ok(error instanceof EvidenceLogError, `expected an EvidenceLogError, got ${error}`)
    return error.code
  }
  return null
}

test('the constants are the published ones', () => {
  assert.equal(EVIDENCE_LOG_FORMAT_VERSION, vectors.evidenceLogFormatVersion)
  assert.equal(LEAF_ENVELOPE_VERSION, vectors.leafEnvelopeVersion)
  assert.equal(LEAF_DOMAIN_TAG, vectors.domainSeparation.leaf.tag)
  assert.equal(CHECKPOINT_DOMAIN_TAG, vectors.domainSeparation.checkpoint.tag)
  assert.equal(LEAF_HASH_PREFIX, 0x00)
  assert.equal(NODE_HASH_PREFIX, 0x01)
  assert.equal(emptyTreeHash(), vectors.hashing.emptyTreeHash)
  assert.deepEqual([...ASSURANCE_PROFILES].sort(), ['CUSTOMER_PRODUCTION', 'PRE_CUSTOMER_DEFAULT'])
  for (const { expect } of vectors.refusals) {
    assert.ok(REFUSAL_CODES.includes(expect), `vector expects undeclared code ${expect}`)
  }
  assert.equal(refusalCode(() => requireSupported('2')), 'UNKNOWN_LOG_VERSION')
})

test('the RFC 6962 known-answer tree reproduces', () => {
  const hashes = vectors.rfc6962KnownAnswers.leafDataHex.map((hex) =>
    leafHashOf(Buffer.from(hex, 'hex')).toString('hex'),
  )
  assert.deepEqual(hashes, vectors.rfc6962KnownAnswers.leafHashes)
  hashes.forEach((_, i) => {
    assert.equal(treeHead(hashes.slice(0, i + 1)), vectors.rfc6962KnownAnswers.rootsBySize[i])
  })
})

test('every published leaf input, leaf hash and tree head reproduces byte for byte', () => {
  Object.entries(vectors.seals).forEach(([id, seal], i) => {
    const input = leafInput(seal)
    assert.equal(sha256hex(input), vectors.leafInputSha256[id], `${id} leaf input`)
    assert.equal(sealLeafHash(seal), vectors.leafHashes[i], `${id} leaf hash`)
  })
  const seal1 = vectors.seals['seal-1']
  const input1 = leafInput(seal1)
  const expectedHeader = `${LEAF_DOMAIN_TAG}\u0000${EVIDENCE_LOG_FORMAT_VERSION}\u0000`
  assert.equal(
    input1.toString('utf8'),
    `${expectedHeader}${vectors.canonical.seal1}`,
    'the readable anchor: header then the published canonical bytes',
  )
  vectors.tree.rootsBySize.forEach((root, i) => {
    assert.equal(treeHead(vectors.leafHashes.slice(0, i + 1)), root, `tree head at size ${i + 1}`)
  })
})

test('the published seal signatures are genuine under the published key', () => {
  const key = createPublicKey({ key: vectors.signingKey.jwk, format: 'jwk' })
  for (const [id, seal] of Object.entries(vectors.seals)) {
    const verifies = verifyEcdsa(
      'sha256',
      sealSigningInput(seal.envelope),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(seal.signature, 'base64url'),
    )
    assert.ok(verifies, `${id} signature must verify`)
  }
})

test('every published inclusion path reproduces and verifies', () => {
  for (const { leafIndex, treeSize, path: proofPath } of vectors.tree.inclusion) {
    const slice = vectors.leafHashes.slice(0, treeSize)
    assert.deepEqual(inclusionPath(leafIndex, slice), proofPath, `PATH(${leafIndex}, ${treeSize})`)
    verifyInclusion({
      leafHash: vectors.leafHashes[leafIndex],
      leafIndex,
      treeSize,
      path: proofPath,
      rootHash: vectors.tree.rootsBySize[treeSize - 1],
    })
  }
})

test('every published consistency proof reproduces and verifies', () => {
  for (const { fromSize, toSize, proof } of vectors.tree.consistency) {
    if (fromSize !== toSize) {
      assert.deepEqual(
        consistencyProof(fromSize, vectors.leafHashes.slice(0, toSize)),
        proof,
        `PROOF(${fromSize}, ${toSize})`,
      )
    }
    verifyConsistency({
      fromSize,
      fromRootHash: vectors.tree.rootsBySize[fromSize - 1],
      toSize,
      toRootHash: vectors.tree.rootsBySize[toSize - 1],
      proof,
    })
  }
})

test('every published checkpoint validates, reproduces its signing input and verifies', () => {
  for (const [id, { checkpoint, signature }] of Object.entries(vectors.checkpoints)) {
    validateCheckpointDocument(checkpoint)
    assert.equal(
      sha256hex(checkpointSigningInput(checkpoint)),
      vectors.checkpointSigningInputSha256[id],
      `${id} signing input`,
    )
    verifyCheckpoint({ checkpoint, signature, jwk: vectors.signingKey.jwk })
    assert.equal(checkpoint.origin, vectors.origin)
    assert.equal(
      checkpoint.rootHash,
      rootHashText(Buffer.from(vectors.tree.rootsBySize[checkpoint.treeSize - 1], 'hex')),
      `${id} names the tree head at its size`,
    )
  }
  const cp1 = vectors.checkpoints['checkpoint-1'].checkpoint
  const expectedHeader = `${CHECKPOINT_DOMAIN_TAG}\u0000${cp1.version}\u0000`
  assert.equal(
    checkpointSigningInput(cp1).toString('utf8'),
    `${expectedHeader}${vectors.canonical.checkpoint1}`,
    'the readable anchor: header then the published canonical bytes',
  )
})

test('the acceptance chain accepts in order, and re-presentation is idempotent', () => {
  let accepted = null
  for (const step of vectors.acceptanceChain.steps) {
    const { checkpoint, signature } = vectors.checkpoints[step.candidate]
    verifyCheckpoint({ checkpoint, signature, jwk: vectors.signingKey.jwk })
    const next = acceptCheckpoint({
      accepted,
      candidate: checkpoint,
      consistencyProof: step.consistencyProof,
    })
    if (step.idempotent) {
      assert.deepEqual(next, accepted, 'the same checkpoint, seen again, changes nothing')
    }
    accepted = next
  }
  assert.equal(accepted.treeSize, 8)
})

test('a leaf not yet checkpointed has no inclusion proof against any published root', () => {
  // Only 3 leaves existed at checkpoint-1: leaf 5 cannot prove into that tree.
  assert.equal(
    refusalCode(() =>
      verifyInclusion({
        leafHash: vectors.leafHashes[5],
        leafIndex: 5,
        treeSize: 3,
        path: inclusionPath(5, vectors.leafHashes),
        rootHash: vectors.tree.rootsBySize[2],
      }),
    ),
    'INCLUSION_PROOF_INVALID',
  )
})

test('every refusal vector refuses with exactly the published code', () => {
  for (const refusal of vectors.refusals) {
    const code = refusalCode(() => {
      switch (refusal.kind) {
        case 'validateCheckpoint':
          return validateCheckpointDocument(refusal.document)
        case 'leaf':
          return leafInput(refusal.seal)
        case 'inclusion': {
          const leafHash = refusal.tamperedSeal
            ? sealLeafHash(refusal.tamperedSeal)
            : refusal.leafHash
          return verifyInclusion({
            leafHash,
            leafIndex: refusal.leafIndex,
            treeSize: refusal.treeSize,
            path: refusal.path,
            rootHash: refusal.rootHashHex,
          })
        }
        case 'consistency':
          return verifyConsistency({
            fromSize: refusal.fromSize,
            fromRootHash: refusal.fromRootHash,
            toSize: refusal.toSize,
            toRootHash: refusal.toRootHash,
            proof: refusal.proof,
          })
        case 'verifyCheckpoint':
          return verifyCheckpoint({
            checkpoint: refusal.checkpoint,
            signature: refusal.signature,
            jwk: refusal.jwk ?? vectors.signingKey.jwk,
          })
        case 'acceptance':
          return acceptCheckpoint({
            accepted: refusal.accepted,
            candidate: refusal.candidate,
            consistencyProof: refusal.consistencyProof,
          })
        default:
          assert.fail(`unknown refusal kind "${refusal.kind}"`)
      }
    })
    assert.equal(code, refusal.expect, `${refusal.id}: ${refusal.description}`)
  }
})

test('the misbehaving-log acceptance candidates are correctly signed — held history is what refuses them', () => {
  const acceptanceRefusals = vectors.refusals.filter((refusal) => refusal.kind === 'acceptance')
  assert.ok(acceptanceRefusals.length >= 6, 'the vectors cover stale, fork (twice), rollback, origin and unproven growth')
  for (const refusal of acceptanceRefusals) {
    verifyCheckpoint({
      checkpoint: refusal.candidate,
      signature: refusal.candidateSignature,
      jwk: vectors.signingKey.jwk,
    })
  }
})

// The cases below are not golden vectors: evidence-log/v1/ is immutable, and
// these pin agreement the published vectors do not reach. Each has a mirrored
// assertion in pruvz-core's EvidenceLogGoldenVectorTests, because a document
// one runtime calls unknown and the other calls malformed is two runtimes
// disagreeing about why a history was refused.
test('an absent or non-string checkpoint version is UNKNOWN, not malformed', () => {
  const { version, ...withoutVersion } = vectors.checkpoints['checkpoint-1'].checkpoint
  assert.equal(version, EVIDENCE_LOG_FORMAT_VERSION)
  assert.equal(refusalCode(() => validateCheckpointDocument(withoutVersion)), 'UNKNOWN_LOG_VERSION')
  assert.equal(
    refusalCode(() => validateCheckpointDocument({ ...withoutVersion, version: 1 })),
    'UNKNOWN_LOG_VERSION',
    'a number where the version belongs names no version this runtime speaks',
  )
})

test('a non-canonical base64url spelling of a signature is refused', () => {
  const { checkpoint, signature } = vectors.checkpoints['checkpoint-1']
  // One signature, two spellings: the final character carries only two
  // meaningful bits, so several characters decode to identical bytes. Exactly
  // one spelling may be accepted, or the same signature has more than one
  // transported form.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const last = signature.at(-1)
  const alias = [...alphabet].find(
    (candidate) =>
      candidate !== last &&
      Buffer.from(signature.slice(0, -1) + candidate, 'base64url').equals(
        Buffer.from(signature, 'base64url'),
      ),
  )
  assert.ok(alias !== undefined, 'the published signature must have an alias spelling to test')
  assert.equal(
    refusalCode(() =>
      verifyCheckpoint({ checkpoint, signature: signature.slice(0, -1) + alias, jwk: vectors.signingKey.jwk }),
    ),
    'MALFORMED_SIGNATURE',
  )
  // The genuine spelling still verifies — the rule rejects the alias, not the signature.
  verifyCheckpoint({ checkpoint, signature, jwk: vectors.signingKey.jwk })
})

test('a held state that is not a previous acceptance is refused, never a runtime error', () => {
  const candidate = vectors.checkpoints['checkpoint-2'].checkpoint
  const accepted = {
    checkpointSequence: 1,
    origin: candidate.origin,
    rootHash: vectors.checkpoints['checkpoint-1'].checkpoint.rootHash,
    treeSize: 3,
  }
  for (const [field, value] of [
    ['rootHash', 'sha256:not-hex'],
    ['rootHash', undefined],
    ['treeSize', 0],
    ['origin', ''],
  ]) {
    assert.equal(
      refusalCode(() => acceptCheckpoint({ accepted: { ...accepted, [field]: value }, candidate })),
      'LOG_MALFORMED',
      `accepted.${field} = ${JSON.stringify(value)}`,
    )
  }
})

test('proof verification refuses garbage before it refuses meaning', () => {
  assert.equal(
    refusalCode(() => verifyInclusion({ leafHash: 'zz', leafIndex: 0, treeSize: 1, path: [], rootHash: vectors.tree.rootsBySize[0] })),
    'LOG_MALFORMED',
  )
  assert.equal(
    refusalCode(() => verifyConsistency({ fromSize: 0, fromRootHash: vectors.tree.rootsBySize[0], toSize: 1, toRootHash: vectors.tree.rootsBySize[0], proof: [] })),
    'LOG_MALFORMED',
  )
  assert.equal(refusalCode(() => leafInput({ envelope: null, signature: 'AA' })), 'LOG_MALFORMED')
  assert.equal(refusalCode(() => validateCheckpointDocument('checkpoint')), 'LOG_MALFORMED')
})
