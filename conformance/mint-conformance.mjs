// One-time minting of conformance/v1/golden-vectors.json — the adversarial
// cross-runtime conformance suite (PRUVZ-97).
//
// This script is committed for provenance, not for re-running: ECDSA is
// randomized and the blinding nonces are drawn fresh, so re-running produces
// different signed bytes. The PUBLISHED vectors are the agreement point, and
// conformance/v1/ is immutable exactly like every other released vector
// directory. A change to the suite is a new conformance version, never a
// regeneration in place.
//
// Everything signed here is signed through the SAME published building blocks
// the verifier checks against (lib/canonical.mjs, lib/trust-registry.mjs,
// lib/evidence-log.mjs, lib/anchoring.mjs), so a minted attack is refused
// because the rules refuse it — not because the fixture and the verifier
// share a shortcut. The expected report of every case was produced by
// lib/verify.mjs at mint time and then reviewed against the layer
// specifications case by case before publication.
//
// The private keys are ephemeral NIST P-256 pairs generated once; the private
// halves were never written anywhere and no longer exist. The "attacker" keys
// (the unpublished seal key, the substitute registry) are just as ephemeral —
// their power in these fixtures is the point: every forged document carries a
// genuine signature over its own bytes, so each case proves its rule rather
// than proving that a broken signature fails. The insider cases (forked,
// rolled-back and insert-forged checkpoints signed by the REAL evidence key)
// model a compromised deployment, which is exactly the adversary the held
// state and consistency rules exist for.
import { createHash, generateKeyPairSync, randomBytes, sign as signEcdsa } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { commitmentDigest, evidenceItemDocument } from '../lib/canonical.mjs'
import { jwkThumbprint, manifestInput, rootPinFromManifest, sealSigningInput } from '../lib/trust-registry.mjs'
import {
  checkpointSigningInput,
  consistencyProof,
  inclusionPath,
  sealLeafHash,
  treeHead,
} from '../lib/evidence-log.mjs'
import { anchorImprint } from '../lib/anchoring.mjs'
import { verifyBundle } from '../lib/verify.mjs'
import { makeAuthority } from '../test/helpers/mint.mjs'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')

const ORIGIN = 'pruvz.ai/evidence-log/conformance'
const ISSUER = 'pruvz.ai'
const TENANT = 'tenant-demo'
const OTHER_TENANT = 'tenant-mallory'
const PROFILE = 'PRE_CUSTOMER_DEFAULT'
const STRONGER_PROFILE = 'CUSTOMER_PRODUCTION'

const base64url = (bytes) => Buffer.from(bytes).toString('base64url')
const clone = (value) => JSON.parse(JSON.stringify(value))

const makeKeyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  return { privateKey, publicKey: { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } }
}

const signP1363 = (privateKey, input) =>
  base64url(signEcdsa('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }))

// ── Keys ────────────────────────────────────────────────────────────────────

const root = { ...makeKeyPair(), keyId: 'conf:keys/trust-root/1' }
const e1 = { ...makeKeyPair(), keyId: 'conf:keys/evidence-signing/1' }
const e2 = { ...makeKeyPair(), keyId: 'conf:keys/evidence-signing/2' }
// The unpublished key: valid ES256, valid envelope, no registry entry.
const unpublished = { ...makeKeyPair(), keyId: 'conf:keys/evidence-signing/unpublished' }
// The substitute trust domain: a complete, internally consistent second
// registry under the same issuer name — everything verifies under ITS root.
const substituteRoot = { ...makeKeyPair(), keyId: 'conf:keys/substitute-trust-root/1' }
const substituteEvidence = { ...makeKeyPair(), keyId: 'conf:keys/substitute-evidence-signing/1' }

// ── Registry timeline v1 → v4 ───────────────────────────────────────────────
// v1: root + E1 active.
// v2: E2 published beside E1 (rotation step one; E2 names E1 as predecessor).
// v3: E1 retired (rotation step two).
// v4: E1 revoked, BACK-DATED into the retirement window — revocation wins.
//     The boundary (2026-07-10T09:15:30Z) falls inside the sealed timeline,
//     so seals exist on both sides of the declared compromise.

// After every sealed committedAt (the packet timeline ends 09:15:45Z), so the
// whole honest seal set sits BEFORE the declared compromise; the one seal
// minted after it is the explicit at-or-after case.
const REVOCATION_BOUNDARY = '2026-07-11T00:00:00Z'

const keyEntry = ({ key, use, validFromUtc, status = 'ACTIVE', retiredAtUtc = null, revokedAtUtc = null, revocationReason = null, predecessorKeyId = null }) => ({
  keyId: key.keyId,
  predecessorKeyId,
  provider: 'local-development',
  publicKey: key.publicKey,
  retiredAtUtc,
  revocationReason,
  revokedAtUtc,
  status,
  suite: 'ES256',
  thumbprint: jwkThumbprint(key.publicKey),
  use,
  validFromUtc,
})

const signManifest = (manifest, signingRoot = root) => ({
  manifest,
  signatures: [
    { keyId: signingRoot.keyId, signature: signP1363(signingRoot.privateKey, manifestInput(manifest)), suite: 'ES256' },
  ],
  attestations: { publications: [], witnesses: [] },
})

const digestOf = (document) =>
  `sha256:${createHash('sha256').update(manifestInput(document.manifest)).digest('hex')}`

const rootEntry = keyEntry({ key: root, use: 'trust-root', validFromUtc: '2026-06-01T00:00:00Z' })
const e1Active = keyEntry({ key: e1, use: 'evidence-signing', validFromUtc: '2026-07-01T00:00:00Z' })
const e2Active = keyEntry({
  key: e2,
  use: 'evidence-signing',
  validFromUtc: '2026-08-05T00:00:00Z',
  predecessorKeyId: e1.keyId,
})

const registryV1 = signManifest({
  formatVersion: '1',
  issuedAtUtc: '2026-08-01T00:00:00Z',
  issuer: ISSUER,
  keys: [rootEntry, e1Active],
  previous: null,
  registryVersion: 1,
})

const registryV2 = signManifest({
  formatVersion: '1',
  issuedAtUtc: '2026-08-05T00:00:00Z',
  issuer: ISSUER,
  keys: [rootEntry, e1Active, e2Active],
  previous: { digest: digestOf(registryV1), registryVersion: 1 },
  registryVersion: 2,
})

const e1Retired = {
  ...e1Active,
  status: 'RETIRED',
  retiredAtUtc: '2026-08-15T00:00:00Z',
}
const registryV3 = signManifest({
  formatVersion: '1',
  issuedAtUtc: '2026-08-15T00:00:00Z',
  issuer: ISSUER,
  keys: [rootEntry, e1Retired, e2Active],
  previous: { digest: digestOf(registryV2), registryVersion: 2 },
  registryVersion: 3,
})

const e1Revoked = {
  ...e1Retired,
  status: 'REVOKED',
  revokedAtUtc: REVOCATION_BOUNDARY,
  revocationReason: 'Key compromise declared 2026-08-20; boundary back-dated to the estimated compromise time.',
}
const registryV4 = signManifest({
  formatVersion: '1',
  issuedAtUtc: '2026-08-20T00:00:00Z',
  issuer: ISSUER,
  keys: [rootEntry, e1Revoked, e2Active],
  previous: { digest: digestOf(registryV3), registryVersion: 3 },
  registryVersion: 4,
})

// A genuine fork of version 2: same version, same root signature discipline,
// one changed byte of history (issuedAtUtc). Only held state can refuse it.
const registryV2Fork = signManifest({
  ...clone(registryV2.manifest),
  issuedAtUtc: '2026-08-05T00:00:01Z',
})

// The substitute trust domain: correct issuer string, coherent chain, wrong root.
const substituteRegistry = signManifest(
  {
    formatVersion: '1',
    issuedAtUtc: '2026-08-01T00:00:00Z',
    issuer: ISSUER,
    keys: [
      keyEntry({ key: substituteRoot, use: 'trust-root', validFromUtc: '2026-06-01T00:00:00Z' }),
      keyEntry({ key: substituteEvidence, use: 'evidence-signing', validFromUtc: '2026-07-01T00:00:00Z' }),
    ],
    previous: null,
    registryVersion: 1,
  },
  substituteRoot,
)

const pin = rootPinFromManifest(registryV1)

// ── Seals ───────────────────────────────────────────────────────────────────

const packet = JSON.parse(
  readFileSync(path.join(repoRoot, 'examples', 'valid', 'verified-refund.packet.json'), 'utf8'),
)
const items = packet.evidence.items

const mintSeal = ({ item, key = e1, tenantId = TENANT, actionId = packet.action.actionId, committedAt = null, profile = PROFILE, subjectOverride = null }) => {
  const envelope = {
    assuranceProfile: profile,
    commitment: {
      digest: commitmentDigest('evidence-item', evidenceItemDocument({ tenantId, actionId, item })),
      digestSuite: 'sha-256',
      kind: 'evidence-item',
      version: '1',
    },
    committedAt: committedAt ?? item.recordedAtUtc,
    signer: { keyId: key.keyId, provider: 'local-development', suite: 'ES256' },
    subject: subjectOverride ?? {
      actionId,
      evidenceId: item.evidenceId,
      sequence: item.sequence,
      tenantId,
    },
    version: '1',
  }
  return { envelope, signature: signP1363(key.privateKey, sealSigningInput(envelope)) }
}

const sealsOf = (mint) => Object.fromEntries(items.map((item) => [item.evidenceId, mint(item)]))

const baseSeals = sealsOf((item) => mintSeal({ item }))
const strongerProfileSeals = sealsOf((item) => mintSeal({ item, profile: STRONGER_PROFILE }))
const otherTenantSeals = sealsOf((item) => mintSeal({ item, tenantId: OTHER_TENANT }))
const otherActionSeals = sealsOf((item) => mintSeal({ item, actionId: 'act_11111111111111111111111111111111' }))
const substituteSeals = sealsOf((item) => mintSeal({ item, key: substituteEvidence }))

// ── Log ─────────────────────────────────────────────────────────────────────

const mintCheckpoint = ({ sequence, issuedAt, leafHashes, key = e2, profile = PROFILE }) => {
  const checkpoint = {
    assuranceProfile: profile,
    checkpointSequence: sequence,
    issuedAt,
    origin: ORIGIN,
    rootHash: `sha256:${treeHead(leafHashes)}`,
    signer: { keyId: key.keyId, provider: 'local-development', suite: 'ES256' },
    treeSize: leafHashes.length,
    version: '1',
  }
  return { checkpoint, signature: signP1363(key.privateKey, checkpointSigningInput(checkpoint)) }
}

const proofsAgainst = (leafHashes, coveringCheckpoint, forIds = items.map((item) => item.evidenceId)) =>
  Object.fromEntries(
    forIds.map((evidenceId, index) => [
      evidenceId,
      {
        leafIndex: index,
        leafHash: leafHashes[index],
        path: inclusionPath(index, leafHashes),
        checkpoint: coveringCheckpoint,
      },
    ]),
  )

const leaves = items.map((item) => sealLeafHash(baseSeals[item.evidenceId]))
const MID = 4
const checkpoint1 = mintCheckpoint({ sequence: 1, issuedAt: '2026-08-10T09:00:00Z', leafHashes: leaves.slice(0, MID) })
const checkpoint2 = mintCheckpoint({ sequence: 2, issuedAt: '2026-08-10T09:01:00Z', leafHashes: leaves })
const baseConsistency = [{ fromSize: MID, toSize: leaves.length, proof: consistencyProof(MID, leaves) }]
const baseProofs = proofsAgainst(leaves, checkpoint2)

// Insider forgeries: genuinely signed by the real evidence key, refutable
// only by history rules.
const forkedLeaves = [leaves[1], leaves[0], ...leaves.slice(2)]
const checkpoint2Fork = mintCheckpoint({ sequence: 2, issuedAt: '2026-08-10T09:01:00Z', leafHashes: forkedLeaves })
const checkpoint3Rollback = mintCheckpoint({ sequence: 3, issuedAt: '2026-08-10T09:02:00Z', leafHashes: leaves.slice(0, MID) })
const insertedLeaf = createHash('sha256').update('forged-record').digest('hex')
const insertedLeaves = [...leaves.slice(0, 2), insertedLeaf, ...leaves.slice(2)]
const checkpoint3Insert = mintCheckpoint({ sequence: 3, issuedAt: '2026-08-10T09:02:00Z', leafHashes: insertedLeaves })

// Stronger-profile checkpoints for the profile cases.
const checkpoint1Stronger = mintCheckpoint({ sequence: 1, issuedAt: '2026-08-10T09:00:00Z', leafHashes: leaves.slice(0, MID), profile: STRONGER_PROFILE })
const checkpoint2Stronger = mintCheckpoint({ sequence: 2, issuedAt: '2026-08-10T09:01:00Z', leafHashes: leaves, profile: STRONGER_PROFILE })

// ── Anchors (synthetic RFC 3161 authority; bindings are the cross-runtime half)

const authority = await makeAuthority()

const mintAnchor = async ({ kind, subject, subjectVersion, anchorId, genTime }) => {
  const blindingNonce = randomBytes(32)
  const requestNonce = Buffer.concat([Buffer.from([0x01]), randomBytes(15)])
  const imprint = anchorImprint(kind, blindingNonce, subject)
  const token = await authority.mintToken({
    imprint: imprint.buffer.slice(imprint.byteOffset, imprint.byteOffset + imprint.byteLength),
    requestNonce,
    genTime,
  })
  return {
    version: '1',
    anchorId,
    trustDomain: 'conformance-tsa',
    status: 'ANCHORED',
    subject: {
      kind,
      origin: kind === 'log-checkpoint' ? subject.checkpoint.origin : subject.manifest.issuer,
      subjectVersion,
    },
    blindingNonce: base64url(blindingNonce),
    requestNonce: base64url(requestNonce),
    receipt: { kind: 'rfc3161-timestamp-token', token },
  }
}

const checkpointAnchor = await mintAnchor({
  kind: 'log-checkpoint',
  subject: { checkpoint: checkpoint2.checkpoint, signature: checkpoint2.signature },
  subjectVersion: 2,
  anchorId: 'anc_conf_checkpoint_2',
  genTime: '2026-08-30T12:00:00Z',
})
const registryAnchor = await mintAnchor({
  kind: 'trust-registry',
  subject: { manifest: registryV2.manifest, signatures: registryV2.signatures },
  subjectVersion: 2,
  anchorId: 'anc_conf_registry_2',
  genTime: '2026-08-30T12:00:01Z',
})

const anchorsFor = (cpAnchor = checkpointAnchor, regAnchor = registryAnchor) => ({
  checkpoints: { 2: { anchors: [cpAnchor] } },
  trustRegistry: { 2: { anchors: [regAnchor] } },
})

// ── Bundles ─────────────────────────────────────────────────────────────────

const bundle = ({ packet: bundlePacket = packet, seals = baseSeals, proofs = baseProofs, checkpoints = [checkpoint1, checkpoint2], consistencyProofs = baseConsistency, trustRegistry = [registryV1, registryV2], anchors = anchorsFor() } = {}) =>
  clone({
    bundleFormatVersion: '1',
    packet: bundlePacket,
    seals,
    proofs,
    checkpoints,
    consistencyProofs,
    trustRegistry,
    anchors,
  })

const bundles = {}

bundles['baseline'] = bundle()
bundles['baseline-no-anchors'] = bundle({ anchors: {} })

// mutate-signed-evidence-field: one summary edited after sealing.
{
  const b = bundle()
  b.packet.evidence.items[2].summary = 'Refund of 30.00 USD approved.'
  bundles['tampered-summary'] = b
}

// timestamp respelling: same instant, different spelling — NOT tampering.
{
  const b = bundle()
  b.packet.evidence.items[2].recordedAtUtc = b.packet.evidence.items[2].recordedAtUtc.replace('Z', '.000Z')
  bundles['respelled-timestamp'] = b
}

// timestamp value change: a different instant — tampering.
{
  const b = bundle()
  b.packet.evidence.items[2].recordedAtUtc = '2026-07-10T09:15:09Z'
  bundles['altered-timestamp'] = b
}

// replay across evidence records: two valid seals swapped.
{
  const b = bundle()
  const [a, c] = [items[0].evidenceId, items[1].evidenceId]
  ;[b.seals[a], b.seals[c]] = [b.seals[c], b.seals[a]]
  bundles['seals-swapped'] = b
}

// replay across tenants / actions: valid seals sealed for another subject.
bundles['sealed-for-other-tenant'] = bundle({ seals: otherTenantSeals, proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })
bundles['sealed-for-other-action'] = bundle({ seals: otherActionSeals, proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })

// key substitution.
bundles['substitute-registry'] = bundle({ seals: substituteSeals, proofs: {}, checkpoints: [], consistencyProofs: [], trustRegistry: [substituteRegistry], anchors: {} })
{
  const b = bundle({ proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })
  b.seals[items[0].evidenceId] = clone(mintSeal({ item: items[0], key: unpublished }))
  bundles['seal-by-unpublished-key'] = b
}
{
  const b = bundle({ proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })
  const rootKeySeal = mintSeal({ item: items[0], key: root })
  b.seals[items[0].evidenceId] = clone(rootKeySeal)
  bundles['seal-by-trust-root-key'] = b
}

// registry lifecycle.
bundles['rotation-retired-after-signing'] = bundle({ trustRegistry: [registryV1, registryV2, registryV3], anchors: {} })
bundles['revoked-boundary'] = bundle({ trustRegistry: [registryV1, registryV2, registryV3, registryV4], anchors: {} })
{
  const b = bundle({ trustRegistry: [registryV1, registryV2, registryV3, registryV4], anchors: {} })
  const lateItem = items[0]
  b.seals[lateItem.evidenceId] = clone(mintSeal({ item: lateItem, committedAt: '2026-07-12T00:00:00Z' }))
  // Its leaf changed, so drop the stale proof and the checkpoints that no
  // longer cover the presented seal set — the case is about the key lifecycle.
  b.proofs = {}
  b.checkpoints = []
  b.consistencyProofs = []
  bundles['sealed-after-revocation-boundary'] = b
}

// registry history attacks (stateful).
bundles['registry-v1-only'] = bundle({ trustRegistry: [registryV1], proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })
bundles['registry-v2-fork'] = bundle({ trustRegistry: [registryV1, registryV2Fork], proofs: {}, checkpoints: [], consistencyProofs: [], anchors: {} })

// Merkle attacks.
{
  // deletion: the LAST record scrubbed from packet, seals and proofs (the
  // last, so the shortened timeline stays schema-consistent and the refusal
  // is purely cryptographic); the remaining proofs are recomputed over the
  // 5-leaf tree, but the served checkpoints still name the honest 6-leaf
  // history.
  const b = bundle({ anchors: {} })
  const removed = items[items.length - 1].evidenceId
  b.packet.evidence.items = b.packet.evidence.items.filter((item) => item.evidenceId !== removed)
  delete b.seals[removed]
  const kept = items.filter((item) => item.evidenceId !== removed)
  const keptLeaves = kept.map((item) => sealLeafHash(baseSeals[item.evidenceId]))
  b.proofs = proofsAgainst(keptLeaves, checkpoint2, kept.map((item) => item.evidenceId))
  b.consistencyProofs = []
  bundles['merkle-leaf-deleted'] = b
}
{
  // reordering: leaves 0 and 1 swapped; proofs recomputed over the reordered
  // tree, checkpoints still the honest ones.
  const b = bundle({ anchors: {} })
  const reorderedIds = [items[1].evidenceId, items[0].evidenceId, ...items.slice(2).map((item) => item.evidenceId)]
  b.proofs = proofsAgainst(forkedLeaves, checkpoint2, reorderedIds)
  b.consistencyProofs = []
  bundles['merkle-leaves-reordered'] = b
}
{
  // corrupt inclusion path: one byte of one sibling flipped.
  const b = bundle({ anchors: {} })
  const target = b.proofs[items[0].evidenceId]
  target.path[0] = target.path[0].replace(/^./, target.path[0][0] === 'a' ? 'b' : 'a')
  bundles['corrupt-inclusion-path'] = b
}
{
  // corrupt consistency proof.
  const b = bundle({ anchors: {} })
  const proof = b.consistencyProofs[0].proof
  proof[0] = proof[0].replace(/^./, proof[0][0] === 'a' ? 'b' : 'a')
  bundles['corrupt-consistency-proof'] = b
}
// fork inside one bundle: both checkpoints numbered 2 served together.
bundles['checkpoint-fork-in-bundle'] = bundle({ checkpoints: [checkpoint1, checkpoint2, checkpoint2Fork], anchors: {} })
// insider fork / rollback / insertion (stateful step twos).
bundles['checkpoint-fork-later'] = bundle({ checkpoints: [checkpoint2Fork], proofs: {}, consistencyProofs: [], anchors: {} })
bundles['checkpoint-rollback'] = bundle({ checkpoints: [checkpoint3Rollback], proofs: {}, consistencyProofs: [], anchors: {} })
{
  const b = bundle({ checkpoints: [checkpoint3Insert], proofs: {}, anchors: {} })
  b.consistencyProofs = [{ fromSize: 6, toSize: 7, proof: consistencyProof(6, insertedLeaves) }]
  bundles['checkpoint-insert-forged'] = b
}
// stale history: only the older checkpoint, presented after the newer one was held.
bundles['checkpoint-stale-history'] = bundle({ checkpoints: [checkpoint1], proofs: proofsAgainst(leaves.slice(0, MID), checkpoint1, items.slice(0, MID).map((item) => item.evidenceId)), consistencyProofs: [], anchors: {} })

// anchors.
{
  // receipt swapped: the registry anchor's token presented on the checkpoint anchor.
  const b = bundle()
  const swapped = clone(checkpointAnchor)
  swapped.receipt = clone(registryAnchor.receipt)
  b.anchors = anchorsFor(swapped)
  bundles['anchor-receipt-swapped'] = b
}
{
  const b = bundle()
  const altered = clone(checkpointAnchor)
  const nonce = Buffer.from(altered.requestNonce, 'base64url')
  nonce[nonce.length - 1] ^= 0x01
  altered.requestNonce = base64url(nonce)
  b.anchors = anchorsFor(altered)
  bundles['anchor-nonce-mismatch'] = b
}
{
  // privacy regression: an anchor subject carrying a tenant identifier.
  const b = bundle()
  const leaky = clone(checkpointAnchor)
  leaky.subject.tenantId = TENANT
  b.anchors = anchorsFor(leaky)
  bundles['anchor-subject-carries-tenant'] = b
}
{
  const b = bundle()
  const pending = clone(checkpointAnchor)
  pending.status = 'PENDING'
  pending.receipt = null
  b.anchors = anchorsFor(pending)
  bundles['anchor-pending'] = b
}
{
  // the published runtime-divergence boundary, at bundle level: the token's
  // signature bytes altered, its imprint untouched.
  const b = bundle()
  const corrupted = clone(checkpointAnchor)
  const der = Buffer.from(corrupted.receipt.token, 'base64')
  der[der.length - 1] ^= 0x01
  corrupted.receipt = { ...corrupted.receipt, token: der.toString('base64') }
  b.anchors = anchorsFor(corrupted)
  bundles['anchor-token-signature-corrupted'] = b
}

// assurance profile.
{
  // Every envelope and checkpoint genuinely claims CUSTOMER_PRODUCTION, but
  // the bundle carries no anchors — the upgraded claim the packet cannot prove.
  const strongerLeaves = items.map((item) => sealLeafHash(strongerProfileSeals[item.evidenceId]))
  const covering = mintCheckpoint({ sequence: 2, issuedAt: '2026-08-10T09:01:00Z', leafHashes: strongerLeaves, profile: STRONGER_PROFILE })
  bundles['stronger-profile-without-anchors'] = bundle({
    seals: strongerProfileSeals,
    checkpoints: [
      mintCheckpoint({ sequence: 1, issuedAt: '2026-08-10T09:00:00Z', leafHashes: strongerLeaves.slice(0, MID), profile: STRONGER_PROFILE }),
      covering,
    ],
    proofs: proofsAgainst(strongerLeaves, covering),
    consistencyProofs: [{ fromSize: MID, toSize: strongerLeaves.length, proof: consistencyProof(MID, strongerLeaves) }],
    anchors: {},
  })
}
{
  // transported profile mutation: checkpoint 1 claims the stronger profile
  // but its signature was made over the honest one. Checkpoint 1 — not the
  // covering checkpoint — because the covering one is also embedded in every
  // inclusion proof, and mutating only the served copy would add a fork on
  // top of the signature failure this case isolates.
  const b = bundle({ anchors: {} })
  b.checkpoints[0].checkpoint.assuranceProfile = STRONGER_PROFILE
  bundles['checkpoint-profile-mutated'] = b
}
{
  // mixed profiles: honest seals, stronger-profile checkpoints (each genuinely signed).
  const strongerLeaves = leaves
  const cp1 = checkpoint1Stronger
  const cp2 = checkpoint2Stronger
  const b = bundle({ checkpoints: [cp1, cp2], proofs: proofsAgainst(strongerLeaves, cp2), anchors: {} })
  bundles['profile-mixed'] = b
}

// truncation: the packet timeline shortened, the seal set left as served.
{
  const b = bundle({ anchors: {} })
  b.packet.evidence.items = b.packet.evidence.items.slice(0, -1)
  bundles['timeline-truncated'] = b
}

// retention: proof-only bundle.
bundles['proof-only'] = bundle({ packet: null })

// ── Raw bundles: cases about SERIALIZATION, which parsed JSON cannot carry ──

/**
 * Re-serializes a value with members in REVERSE key order and indentation —
 * a logically identical document in a spelling no canonical serializer would
 * produce. A conformant verifier judges the value, never the spelling.
 */
const reverseOrderJson = (value, indent = '') => {
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]'
    const inner = value.map((item) => `${indent}  ${reverseOrderJson(item, `${indent}  `)}`).join(',\n')
    return `[\n${inner}\n${indent}]`
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort().reverse()
    if (keys.length === 0) return '{}'
    const inner = keys
      .map((key) => `${indent}  ${JSON.stringify(key)}: ${reverseOrderJson(value[key], `${indent}  `)}`)
      .join(',\n')
    return `{\n${inner}\n${indent}}`
  }
  return JSON.stringify(value)
}

const baselineJson = JSON.stringify(bundles['baseline'], null, 1)
const summaryNeedle = JSON.stringify(items[2].summary)
if (!baselineJson.includes(`"summary": ${summaryNeedle}`)) {
  throw new Error('duplicate-key fixture: could not locate the summary member to duplicate')
}

const rawBundles = {
  'baseline-reserialized': reverseOrderJson(bundles['baseline']),
  // The first occurrence is what a human reviewer reads; the last is what a
  // last-wins parser commits to. Two documents in one byte string — refused.
  'duplicate-member': baselineJson.replace(
    `"summary": ${summaryNeedle}`,
    `"summary": ${summaryNeedle}, "summary": ${JSON.stringify('Refund of 30.00 USD approved.')}`,
  ),
  'truncated-json': baselineJson.slice(0, 120),
}

// ── Cases ───────────────────────────────────────────────────────────────────
// Every case names the attack-matrix row it covers. A multi-step case threads
// the state a previous step returned, exactly as a CLI caller threads --state.
// `expect` is generated by lib/verify.mjs at mint time and frozen after review;
// no runtime may read it to produce its own answer.

const TENANT_OPTION = { tenant: TENANT }

const cases = [
  // Positive agreement baselines.
  { id: 'valid-full-witnessed', attack: 'baseline', description: 'The complete coherent bundle with pinned TSA roots — the only reachable FULLY_VERIFIED.', steps: [{ bundle: 'baseline', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'valid-full-binding-only', attack: 'baseline', description: 'The same bundle without pinned TSA roots: bindings check, authority honestly NOT_EVALUATED.', steps: [{ bundle: 'baseline', options: { ...TENANT_OPTION } }] },
  { id: 'valid-no-anchors-cost-gated', attack: 'assurance-omission', description: 'PRE_CUSTOMER_DEFAULT material with no anchors: the cost-gated absence is reported, and FULLY_VERIFIED is unreachable.', steps: [{ bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } }] },
  { id: 'valid-state-idempotent', attack: 'baseline', description: 'Replaying the accepted bundle against its own returned state changes nothing.', steps: [
    { bundle: 'baseline', options: { ...TENANT_OPTION, tsaRoots: true } },
    { bundle: 'baseline', options: { ...TENANT_OPTION, tsaRoots: true, state: 'held' } },
  ] },

  // Serialization: the value is judged, never the spelling — and one byte
  // string that parses as two documents is refused as unusable input.
  { id: 'equivalent-serialization-accepted', attack: 'serialization-ambiguity', description: 'The baseline re-serialized with reversed member order and whitespace is the same logical bundle and yields the identical report.', steps: [{ rawBundle: 'baseline-reserialized', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'duplicate-member-refused', attack: 'serialization-ambiguity', description: 'A bundle file with a duplicated member name is two documents in one byte string; every runtime refuses it as unusable input.', steps: [{ rawBundle: 'duplicate-member', options: { ...TENANT_OPTION, tsaRoots: true }, expect: { outcome: 'UNUSABLE_INPUT' } }] },
  { id: 'truncated-export-refused', attack: 'truncation', description: 'A truncated export is not a weaker bundle; it is unusable input.', steps: [{ rawBundle: 'truncated-json', options: { ...TENANT_OPTION }, expect: { outcome: 'UNUSABLE_INPUT' } }] },

  // Mutation of committed material.
  { id: 'mutated-evidence-field', attack: 'mutate-signed-field', description: 'One summary edited after sealing: the record no longer hashes to the digest its seal names.', steps: [{ bundle: 'tampered-summary', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'respelled-timestamp-equivalent', attack: 'money-timestamp-normalization', description: 'The same instant respelled with a zero fraction commits identically — normalization is not tampering, and the report equals the baseline.', steps: [{ bundle: 'respelled-timestamp', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'altered-timestamp-value', attack: 'money-timestamp-normalization', description: 'A different instant is a different committed value.', steps: [{ bundle: 'altered-timestamp', options: { ...TENANT_OPTION, tsaRoots: true } }] },

  // Replay.
  { id: 'replay-across-evidence', attack: 'replay', description: 'Two valid seals swapped between records: each signature is genuine and attests to the other subject.', steps: [{ bundle: 'seals-swapped', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'replay-across-tenant', attack: 'replay', description: 'Seals genuinely made for another tenant, presented under the caller-pinned tenant.', steps: [{ bundle: 'sealed-for-other-tenant', options: { ...TENANT_OPTION } }] },
  { id: 'replay-across-action', attack: 'replay', description: 'Seals genuinely made for another action over identical content.', steps: [{ bundle: 'sealed-for-other-action', options: { ...TENANT_OPTION } }] },

  // Key substitution and key misuse.
  { id: 'substituted-registry', attack: 'key-substitution', description: 'A complete, internally consistent registry under a different root: everything verifies under ITS root and nothing verifies under the pin.', steps: [{ bundle: 'substitute-registry', options: { ...TENANT_OPTION } }] },
  { id: 'seal-by-unpublished-key', attack: 'key-substitution', description: 'A valid ES256 seal by a key the registry never published.', steps: [{ bundle: 'seal-by-unpublished-key', options: { ...TENANT_OPTION } }] },
  { id: 'seal-by-trust-root-key', attack: 'key-substitution', description: 'The trust root sealing evidence: the two powers that must never meet.', steps: [{ bundle: 'seal-by-trust-root-key', options: { ...TENANT_OPTION } }] },

  // Key lifecycle: rotation, revocation, the compromise boundary.
  { id: 'rotation-preserves-history', attack: 'rotation', description: 'Seals made while their key was ACTIVE stay valid after the key is retired; the retirement is noted, never punished.', steps: [{ bundle: 'rotation-retired-after-signing', options: { ...TENANT_OPTION } }] },
  { id: 'sealed-before-compromise-boundary', attack: 'compromise-boundary', description: 'Seals made before the declared, back-dated compromise: weakened (the boundary compares against self-asserted time), never full.', steps: [{ bundle: 'revoked-boundary', options: { ...TENANT_OPTION } }] },
  { id: 'sealed-after-compromise-boundary', attack: 'compromise-boundary', description: 'A seal whose committedAt falls at or after the declared compromise is a refusal.', steps: [{ bundle: 'sealed-after-revocation-boundary', options: { ...TENANT_OPTION } }] },

  // Registry history (stateful).
  { id: 'registry-rollback-refused', attack: 'registry-rollback', description: 'A correctly signed OLDER registry presented to a verifier that already accepted a newer one — how a revocation is hidden.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'registry-v1-only', options: { ...TENANT_OPTION, state: 'held' } },
  ] },
  { id: 'registry-fork-refused', attack: 'registry-rollback', description: 'A second, genuinely signed manifest at an already-held version: one version has one history.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'registry-v2-fork', options: { ...TENANT_OPTION, state: 'held' } },
  ] },

  // Merkle history.
  { id: 'merkle-leaf-deleted', attack: 'merkle-delete-insert-reorder', description: 'A record scrubbed from packet, seals and proofs: the remaining proofs no longer lead to the honest checkpointed head.', steps: [{ bundle: 'merkle-leaf-deleted', options: { ...TENANT_OPTION } }] },
  { id: 'merkle-leaves-reordered', attack: 'merkle-delete-insert-reorder', description: 'Two leaves swapped and proofs recomputed: order is data, and the honest head refuses the reordered tree.', steps: [{ bundle: 'merkle-leaves-reordered', options: { ...TENANT_OPTION } }] },
  { id: 'merkle-insert-forged', attack: 'merkle-delete-insert-reorder', description: 'An insider inserts a leaf inside checkpointed history and signs the new head: no consistency proof can connect the honest head to it.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'checkpoint-insert-forged', options: { ...TENANT_OPTION, state: 'held' } },
  ] },
  { id: 'corrupt-inclusion-proof', attack: 'proof-corruption', description: 'One flipped byte in an inclusion path.', steps: [{ bundle: 'corrupt-inclusion-path', options: { ...TENANT_OPTION } }] },
  { id: 'corrupt-consistency-proof', attack: 'proof-corruption', description: 'One flipped byte in a consistency proof.', steps: [{ bundle: 'corrupt-consistency-proof', options: { ...TENANT_OPTION } }] },

  // Checkpoint history (stateful) — every forged document genuinely signed.
  { id: 'checkpoint-fork-in-bundle', attack: 'fork-stale-checkpoint', description: 'Two genuinely signed checkpoints numbered 2 with different heads served in one bundle.', steps: [{ bundle: 'checkpoint-fork-in-bundle', options: { ...TENANT_OPTION } }] },
  { id: 'checkpoint-fork-held-state', attack: 'fork-stale-checkpoint', description: 'The forked head presented to a verifier that already accepted the honest one.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'checkpoint-fork-later', options: { ...TENANT_OPTION, state: 'held' } },
  ] },
  { id: 'checkpoint-rollback-refused', attack: 'fork-stale-checkpoint', description: 'A later, genuinely signed checkpoint covering fewer leaves: append-only means the tree never shrinks.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'checkpoint-rollback', options: { ...TENANT_OPTION, state: 'held' } },
  ] },
  { id: 'stale-history-not-current', attack: 'fork-stale-checkpoint', description: 'An old export presented after newer history was held: reported as unconnected history, and the held state never regresses.', steps: [
    { bundle: 'baseline-no-anchors', options: { ...TENANT_OPTION } },
    { bundle: 'checkpoint-stale-history', options: { ...TENANT_OPTION, state: 'held' } },
  ] },

  // Anchors.
  { id: 'anchor-receipt-swapped', attack: 'anchor-swap', description: 'A genuine receipt for the registry presented as the checkpoint anchor: the token binds to something else.', steps: [{ bundle: 'anchor-receipt-swapped', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'anchor-nonce-mismatch', attack: 'anchor-swap', description: 'A replayed token: the record names a request nonce the token does not carry.', steps: [{ bundle: 'anchor-nonce-mismatch', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'anchor-wrong-authority-root', attack: 'anchor-swap', description: 'The genuine token verified against a different pinned authority root: trust is the caller pin, never the embedded chain.', steps: [{ bundle: 'baseline', options: { ...TENANT_OPTION, tsaRoots: 'wrong' } }] },
  { id: 'anchor-token-signature-corrupted', attack: 'anchor-swap', description: 'The token binds (its imprint is untouched) but its signature bytes were altered: half two refuses what half one alone cannot.', steps: [{ bundle: 'anchor-token-signature-corrupted', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'anchor-pending-not-witnessed', attack: 'assurance-omission', description: 'A pending anchor is not a witness, and is never reported as one.', steps: [{ bundle: 'anchor-pending', options: { ...TENANT_OPTION, tsaRoots: true } }] },
  { id: 'anchor-subject-carries-tenant', attack: 'anchor-privacy', description: 'An anchor whose subject carries a tenant identifier violates the privacy boundary by construction and is refused as malformed.', steps: [{ bundle: 'anchor-subject-carries-tenant', options: { ...TENANT_OPTION, tsaRoots: true } }] },

  // Assurance profile.
  { id: 'stronger-profile-unproven', attack: 'assurance-omission', description: 'Material genuinely claiming CUSTOMER_PRODUCTION with no anchors: the claim the packet cannot prove never reaches FULLY_VERIFIED.', steps: [{ bundle: 'stronger-profile-without-anchors', options: { ...TENANT_OPTION } }] },
  { id: 'profile-mutated-in-transit', attack: 'profile-metadata', description: 'A transported checkpoint whose profile was upgraded after signing: the signed bytes changed.', steps: [{ bundle: 'checkpoint-profile-mutated', options: { ...TENANT_OPTION } }] },
  { id: 'profile-mixed', attack: 'profile-metadata', description: 'Seals and checkpoints genuinely produced under different profiles: reported, never averaged.', steps: [{ bundle: 'profile-mixed', options: { ...TENANT_OPTION } }] },

  // Truncation and retention.
  { id: 'timeline-truncated', attack: 'truncation', description: 'The packet timeline shortened while the served seal set still names the removed record.', steps: [{ bundle: 'timeline-truncated', options: { ...TENANT_OPTION } }] },
  { id: 'retained-proof-only', attack: 'retained-proof', description: 'Proof material without the payload: proves the sealed record existed and is covered — and is never presented as payload verification.', steps: [{ bundle: 'proof-only', options: { ...TENANT_OPTION, tsaRoots: true } }] },
]

// ── Expected reports: produced by lib/verify.mjs, frozen after review ───────

const wrongAuthority = await makeAuthority()

const runStep = async (step, heldState) => {
  const input = step.rawBundle !== undefined ? rawBundles[step.rawBundle] : JSON.stringify(bundles[step.bundle])
  const parsed = JSON.parse(input)
  return verifyBundle(clone(parsed), {
    pin,
    expectedTenantId: step.options.tenant ?? null,
    tsaRoots: step.options.tsaRoots === true ? [authority.rootPem] : step.options.tsaRoots === 'wrong' ? [wrongAuthority.rootPem] : null,
    state: step.options.state === 'held' ? heldState : null,
  })
}

for (const conformanceCase of cases) {
  let heldState = null
  for (const step of conformanceCase.steps) {
    if (step.expect?.outcome === 'UNUSABLE_INPUT') continue
    const report = await runStep(step, heldState)
    heldState = clone(report.state)
    step.expect = {
      outcome: 'REPORT',
      verdict: report.verdict,
      reasonCodes: report.reasonCodes,
      dimensions: Object.fromEntries(
        Object.entries(report.dimensions).map(([name, dimension]) => [name, dimension.status ?? 'COMPOSITE']),
      ),
      state: clone(report.state),
    }
  }
}

// Review table before freezing.
for (const conformanceCase of cases) {
  for (const [index, step] of conformanceCase.steps.entries()) {
    const suffix = conformanceCase.steps.length > 1 ? `#${index + 1}` : ''
    if (step.expect.outcome === 'UNUSABLE_INPUT') {
      console.log(`${conformanceCase.id}${suffix}: UNUSABLE_INPUT`)
    } else {
      console.log(`${conformanceCase.id}${suffix}: ${step.expect.verdict} [${step.expect.reasonCodes.join(', ')}]`)
    }
  }
}

const vectors = {
  conformanceFormatVersion: '1',
  howTheseWereProduced:
    'Minted for the PRUVZ-97 release by conformance/mint-conformance.mjs (committed for provenance; ' +
    're-running produces different signed bytes because ECDSA and the nonces are randomized — the ' +
    'published bytes are the agreement point and conformance/v1/ is immutable). An ephemeral four-version ' +
    'trust registry (publish, rotate in, retire, back-dated revoke), seals over the published ' +
    'examples/valid/verified-refund.packet.json, an RFC 6962 log with genuinely signed forked, ' +
    'rolled-back and insert-forged checkpoints modeling a compromised deployment, and a synthetic ' +
    'RFC 3161 authority whose root is published here for pinning. Expected reports were produced by ' +
    'lib/verify.mjs at mint time and reviewed case by case against the layer specifications before ' +
    'publication. Every conformant runtime must reproduce every verdict, reason-code set, dimension ' +
    'status and returned state independently, without reading the expectations.',
  attackMatrix: Object.fromEntries(
    [...new Set(cases.map((conformanceCase) => conformanceCase.attack))].map((attack) => [
      attack,
      cases.filter((conformanceCase) => conformanceCase.attack === attack).map((conformanceCase) => conformanceCase.id),
    ]),
  ),
  pin,
  tsaRoots: [authority.rootPem],
  wrongTsaRoots: [wrongAuthority.rootPem],
  bundles,
  rawBundles,
  cases,
}

writeFileSync(path.join(repoRoot, 'conformance', 'v1', 'golden-vectors.json'), `${JSON.stringify(vectors, null, 1)}\n`)
console.log('\nwrote conformance/v1/golden-vectors.json:', Object.keys(bundles).length, 'bundles,', cases.length, 'cases')
