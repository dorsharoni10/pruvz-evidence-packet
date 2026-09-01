// The offline verifier (PRUVZ-88): the published verifier/v1 golden cases are
// replayed exactly, and the behaviours no static vector can pin — held-state
// continuity, defective authorities, freshly minted tampering — are exercised
// through the minting fixture. Everything here runs without any network
// access; that is not a test convenience but the product property under test.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { verifyBundle } from '../lib/verify.mjs'
import { anchorInput, verifyAnchorBinding } from '../lib/anchoring.mjs'
import { embeddedCertificates, verifyTimestampAuthority } from '../lib/anchor-authority.mjs'
import { makeAuthority, mintBundle } from './helpers/mint.mjs'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const vectors = JSON.parse(readFileSync(path.join(repoRoot, 'verifier', 'v1', 'golden-vectors.json'), 'utf8'))
const anchoringVectors = JSON.parse(
  readFileSync(path.join(repoRoot, 'anchoring', 'v1', 'golden-vectors.json'), 'utf8'),
)

const clone = (value) => JSON.parse(JSON.stringify(value))

const dimensionStatuses = (report) =>
  Object.fromEntries(Object.entries(report.dimensions).map(([name, dimension]) => [name, dimension.status]))

// ── The published golden cases, replayed exactly ────────────────────────────

// Documented erratum (docs/VERIFIER.md, PRUVZ-97): the immutable verifier/v1
// vectors pinned `ANCHOR_RECEIPT_SIGNATURE_INVALID`, a code outside the
// anchoring layer's closed vocabulary. The accurate code — the one
// docs/ANCHORING.md §10 and the immutable anchoring/v1 runtimeDivergence
// require — is `ANCHOR_SIGNATURE_INVALID`, and every replay of verifier/v1
// substitutes it. conformance/v1 pins the corrected code directly.
const VERIFIER_V1_ERRATA = { ANCHOR_RECEIPT_SIGNATURE_INVALID: 'ANCHOR_SIGNATURE_INVALID' }
const withErrata = (reasonCodes) => reasonCodes.map((code) => VERIFIER_V1_ERRATA[code] ?? code).sort()

for (const goldenCase of vectors.cases) {
  test(`golden case: ${goldenCase.id}`, async () => {
    const report = await verifyBundle(clone(vectors.bundles[goldenCase.bundle]), {
      pin: goldenCase.options.pinRootOverride
        ? { issuer: vectors.pin.issuer, root: goldenCase.options.pinRootOverride }
        : vectors.pin,
      expectedTenantId: goldenCase.options.tenant ?? null,
      tsaRoots: goldenCase.options.tsaRoots ? vectors.tsaRoots : null,
    })
    assert.equal(report.verdict, goldenCase.expect.verdict, goldenCase.description)
    assert.deepEqual(report.reasonCodes, withErrata(goldenCase.expect.reasonCodes))
    assert.deepEqual(dimensionStatuses(report), goldenCase.expect.dimensions)
  })
}

test('the only FULLY_VERIFIED golden case is the complete bundle', () => {
  const fully = vectors.cases.filter((goldenCase) => goldenCase.expect.verdict === 'FULLY_VERIFIED')
  assert.deepEqual(
    fully.map((goldenCase) => goldenCase.id),
    ['full'],
    'FULLY_VERIFIED must be unreachable for every degraded case',
  )
})

// ── Dimensional honesty on freshly minted bundles ───────────────────────────

test('a complete minted bundle reaches FULLY_VERIFIED and returns continuable state', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-demo', tsaRoots })
  assert.equal(report.verdict, 'FULLY_VERIFIED')
  assert.equal(report.dimensions.anchors.status, 'WITNESSED')
  assert.equal(report.state.registry.registryVersion, 1)
  assert.equal(report.state.checkpoint.treeSize, bundle.packet.evidence.items.length)
})

test('a missing seal weakens the verdict, never silently passes', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  const first = Object.keys(bundle.seals)[0]
  delete bundle.seals[first]
  delete bundle.proofs[first]
  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-demo', tsaRoots })
  assert.equal(report.verdict, 'PARTIALLY_VERIFIED')
  assert.ok(report.reasonCodes.includes('EVIDENCE_UNSEALED'))
  assert.equal(report.dimensions.seals.status, 'INCOMPLETE')
})

test('a wrong expected tenant is a subject mismatch, not a labeling nuance', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-other', tsaRoots })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('SUBJECT_MISMATCH'))
})

test('a pre-1.5.0 packet honestly reports that commitments cannot be recomputed', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  bundle.packet.packetFormatVersion = '1.4.0'
  for (const item of bundle.packet.evidence.items) {
    delete item.runId
    delete item.schemaVersion
    delete item.clientOperationId
    delete item.payloadMetadata
  }
  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-demo', tsaRoots })
  assert.equal(report.verdict, 'PARTIALLY_VERIFIED')
  assert.ok(report.reasonCodes.includes('COMMITMENT_FIELDS_UNAVAILABLE'))
  assert.equal(report.dimensions.commitment.status, 'NOT_CHECKED')
  // The seals still verify — origin and subject hold; only content is open.
  assert.notEqual(report.dimensions.seals.status, 'INVALID')
})

test('an inclusion proof pointing at a different leaf is a refusal', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  const ids = Object.keys(bundle.proofs)
  const swapped = bundle.proofs[ids[0]]
  bundle.proofs[ids[0]] = { ...bundle.proofs[ids[1]] }
  bundle.proofs[ids[1]] = { ...swapped }
  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-demo', tsaRoots })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('LEAF_SEAL_MISMATCH'))
})

// ── Held state: rollback and fork become refusals only for a verifier that keeps it ──

test('held state refuses a fork: a second checkpoint at the same sequence with another head', async () => {
  const minted = await mintBundle({ withAnchors: false })
  const first = await verifyBundle(clone(minted.bundle), {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
  })
  assert.equal(first.verdict, 'PARTIALLY_VERIFIED') // no anchors, by construction

  // A different history minted under the SAME registry: re-seal after altering
  // an item, so checkpoint 2 names another root at the same sequence.
  const { makeSeals, makeLog } = await import('./helpers/mint.mjs')
  const forkedPacket = clone(minted.bundle.packet)
  forkedPacket.evidence.items[0].summary = 'A different history.'
  const forkedSeals = makeSeals(forkedPacket, minted.registry.evidence)
  const forkedLog = makeLog(forkedPacket, forkedSeals, minted.registry.evidence)
  const forkedBundle = {
    ...clone(minted.bundle),
    packet: forkedPacket,
    seals: forkedSeals,
    proofs: forkedLog.proofs,
    checkpoints: forkedLog.checkpoints,
    consistencyProofs: forkedLog.consistencyProofs,
  }

  const second = await verifyBundle(forkedBundle, {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
    state: first.state,
  })
  assert.equal(second.verdict, 'NOT_VERIFIED')
  assert.ok(second.reasonCodes.includes('CHECKPOINT_FORK'))
})

test('an export older than the held state never regresses it, and is reported unconnected', async () => {
  const minted = await mintBundle({ withAnchors: false })
  const first = await verifyBundle(clone(minted.bundle), {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
  })

  // A historical export: only the earlier, smaller checkpoint. Not an attack —
  // but it cannot be connected forward, and the held state must survive it.
  const historical = clone(minted.bundle)
  const older = historical.checkpoints[0] // sequence 1, smaller tree
  historical.checkpoints = [older]
  historical.consistencyProofs = []
  historical.proofs = {}
  historical.seals = Object.fromEntries(
    Object.entries(historical.seals).slice(0, older.checkpoint.treeSize),
  )
  const second = await verifyBundle(historical, {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
    state: first.state,
  })
  assert.equal(second.verdict, 'PARTIALLY_VERIFIED')
  assert.ok(second.reasonCodes.includes('CONSISTENCY_NOT_PROVEN'))
  assert.deepEqual(second.state.checkpoint, first.state.checkpoint, 'held state must not regress')
})


test('state from another trust anchor is refused, not compared', async () => {
  const minted = await mintBundle({ withAnchors: false })
  const report = await verifyBundle(clone(minted.bundle), {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
    state: {
      registry: { issuer: minted.pin.issuer, root: 'sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', registryVersion: 1, digest: 'sha256:00' },
      checkpoint: null,
    },
  })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('ROOT_MISMATCH'))
})

test('an unverifiable checkpoint is reported but never remembered', async () => {
  // A bundle served without a trust registry is a published, PARTIALLY_VERIFIED
  // shape, so it must not be able to plant a head in the verifier's held
  // history: held state never regresses, so one planted head would make every
  // genuine export afterwards look like stale history, permanently.
  const minted = await mintBundle({ withAnchors: false })
  const planting = clone(minted.bundle)
  planting.trustRegistry = null
  planting.proofs = {}
  planting.consistencyProofs = []
  const newest = planting.checkpoints[planting.checkpoints.length - 1]
  newest.checkpoint.checkpointSequence = 99
  newest.checkpoint.treeSize += 7
  newest.checkpoint.rootHash = `sha256:${'ab'.repeat(32)}`
  planting.checkpoints = [newest]

  const planted = await verifyBundle(planting, { pin: minted.pin, expectedTenantId: 'tenant-demo' })
  assert.equal(planted.verdict, 'PARTIALLY_VERIFIED')
  assert.ok(planted.reasonCodes.includes('REGISTRY_ABSENT'))
  assert.equal(planted.state.checkpoint, null, 'an unverified checkpoint must not enter held state')

  // The genuine export that follows is untouched by what that bundle carried.
  const genuine = await verifyBundle(clone(minted.bundle), {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
    state: planted.state,
  })
  assert.ok(!genuine.reasonCodes.includes('CONSISTENCY_NOT_PROVEN'))
  assert.equal(genuine.state.checkpoint.checkpointSequence, 2)
})

test('two disagreeing checkpoints at one sequence are a fork, wherever they came from', async () => {
  const minted = await mintBundle({ withAnchors: false })
  const forked = clone(minted.bundle)
  const first = forked.checkpoints[0]
  const contradiction = clone(first)
  contradiction.checkpoint.rootHash = `sha256:${'cd'.repeat(32)}`
  forked.checkpoints = [first, contradiction, ...forked.checkpoints.slice(1)]
  const report = await verifyBundle(forked, { pin: minted.pin, expectedTenantId: 'tenant-demo' })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('CHECKPOINT_FORK'))
})

test('one checkpoint served twice in different key order is one checkpoint', async () => {
  // The same checkpoint reaches a bundle from two endpoints, and a holder may
  // reformat a saved export. Key order is not evidence of a forked log, and
  // reporting it as one would accuse genuine evidence of forgery.
  const minted = await mintBundle({ withAnchors: false })
  const reserialized = clone(minted.bundle)
  const first = reserialized.checkpoints[0]
  reserialized.checkpoints = [
    first,
    {
      signature: first.signature,
      checkpoint: Object.fromEntries(Object.entries(first.checkpoint).reverse()),
    },
    ...reserialized.checkpoints.slice(1),
  ]
  const report = await verifyBundle(reserialized, { pin: minted.pin, expectedTenantId: 'tenant-demo' })
  assert.notEqual(report.verdict, 'NOT_VERIFIED')
  assert.ok(!report.reasonCodes.includes('CHECKPOINT_FORK'))
})

test('a held state that is not what a previous run returned is unusable input, not a verdict', async () => {
  // Refusing the file is the honest answer. Reinterpreting it would either
  // accuse genuine evidence of forgery (a half-written checkpoint fails the
  // log's document rules) or silently switch the protection off (an empty
  // object compares against nothing).
  const minted = await mintBundle({ withAnchors: false })
  const broken = [
    { registry: null, checkpoint: {} },
    { registry: null, checkpoint: { checkpointSequence: 2 } },
    { registry: null, checkpoint: null, lastRun: '2026-08-31' },
  ]
  for (const state of broken) {
    await assert.rejects(
      () => verifyBundle(clone(minted.bundle), { pin: minted.pin, state }),
      (error) => error.name === 'VerifierError' && error.code === 'STATE_MALFORMED',
    )
  }
})

test('a tenant the caller pinned is checked even when the packet is gone', async () => {
  // --tenant is a pin in every bundle shape. A proof-only export has no items
  // to bind the subject against, which must never mean the supplied tenant
  // goes unchecked against the seals that are present.
  const minted = await mintBundle({ withAnchors: false })
  const proofOnly = clone(minted.bundle)
  proofOnly.packet = null
  const report = await verifyBundle(proofOnly, {
    pin: minted.pin,
    expectedTenantId: 'tenant-somebody-else',
  })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('TENANT_MISMATCH'))
})

// ── Anchor half two: the authority itself ───────────────────────────────────

test('the real published receipts verify against their own pinned chain', async () => {
  for (const bindingCase of Object.values(anchoringVectors.bindingCases)) {
    const record = clone(bindingCase.record)
    if (record.receipt.token.startsWith('@')) {
      record.receipt.token = anchoringVectors.receipts[record.receipt.token.slice(1)]
    }
    const subject = anchoringVectors.subjects[bindingCase.subjectRef]
    const binding = verifyAnchorBinding({ record, subject })
    assert.equal(binding.authorityVerified, false, 'half one never claims the authority half')

    const chain = embeddedCertificates(record.receipt.token)
    const result = await verifyTimestampAuthority({
      token: record.receipt.token,
      roots: [chain[chain.length - 1]],
      imprintInput: anchorInput(record.subject.kind, record.blindingNonce, subject),
    })
    assert.equal(result.genTime, bindingCase.expect.genTime)
    assert.equal(result.policyOid, bindingCase.expect.policyOid)
  }
})

test('the published runtimeDivergence boundary: half one binds, half two refuses', async () => {
  const divergence = anchoringVectors.runtimeDivergence[0]
  const record = clone(divergence.record)
  if (record.receipt.token.startsWith('@')) {
    record.receipt.token = anchoringVectors.receipts[record.receipt.token.slice(1)]
  }
  const subject = anchoringVectors.subjects[divergence.subjectRef ?? 'log-checkpoint']
  verifyAnchorBinding({ record, subject }) // must not throw: the imprint is untouched

  const chain = embeddedCertificates(record.receipt.token)
  await assert.rejects(
    verifyTimestampAuthority({
      token: record.receipt.token,
      roots: [chain[chain.length - 1]],
      imprintInput: anchorInput(record.subject.kind, record.blindingNonce, subject),
    }),
    (error) => error.code === 'ANCHOR_SIGNATURE_INVALID',
  )
})

test('a token from an unpinned authority is refused however valid it is', async () => {
  const { bundle, pin, tsaRoots } = await mintBundle({})
  const stranger = await makeAuthority()
  const report = await verifyBundle(bundle, {
    pin,
    expectedTenantId: 'tenant-demo',
    tsaRoots: [stranger.rootPem], // valid tokens, wrong pinned root
  })
  assert.equal(report.verdict, 'NOT_VERIFIED')
  assert.ok(report.reasonCodes.includes('ANCHOR_UNTRUSTED_AUTHORITY'))
  void tsaRoots
})

test('a cross-signed copy of the pinned root embedded in the token cannot displace the anchor', async () => {
  // Public authorities embed their root twice: self-signed, and cross-signed
  // by an older root nobody pins (DigiCert Trusted Root G4 under DigiCert
  // Assured ID Root CA). The pinned root is the anchor; the look-alike is at
  // most an intermediate and must never turn a genuine token into a refusal.
  const { bundle, pin, tsaRoots } = await mintBundle({ authorityOptions: { crossSignedRoot: true } })
  const token = bundle.anchors.checkpoints['2'].anchors[0].receipt.token
  const embedded = embeddedCertificates(token)
  assert.equal(embedded.length, 3, 'the minted token embeds root, cross-signed root and leaf')

  const report = await verifyBundle(bundle, { pin, expectedTenantId: 'tenant-demo', tsaRoots })
  assert.equal(report.verdict, 'FULLY_VERIFIED')
  assert.equal(report.dimensions.anchors.status, 'WITNESSED')

  // Still a refusal against a stranger's root that carries the SAME NAME as
  // the real one but a different key: the name-based exclusion drops both
  // embedded copies of the root, the leaf's signature does not verify under
  // the stranger, and nothing is admitted by name alone.
  const stranger = await makeAuthority()
  const refused = await verifyBundle(bundle, {
    pin,
    expectedTenantId: 'tenant-demo',
    tsaRoots: [stranger.rootPem],
  })
  assert.equal(refused.verdict, 'NOT_VERIFIED')
  assert.ok(refused.reasonCodes.includes('ANCHOR_UNTRUSTED_AUTHORITY'))
})

test('a non-critical timestamping purpose is refused', async () => {
  const authority = await makeAuthority({ ekuCritical: false })
  const imprint = Buffer.alloc(32, 7)
  const requestNonce = Buffer.from([1, 2, 3, 4, 5, 6, 7, 8])
  const token = await authority.mintToken({
    imprint: imprint.buffer.slice(0, 32),
    requestNonce,
  })
  await assert.rejects(
    verifyTimestampAuthority({ token, roots: [authority.rootPem], imprintInput: Buffer.from([1]) }),
    (error) => error.code === 'ANCHOR_UNTRUSTED_AUTHORITY' && /critical/u.test(error.message),
  )
})

test('a certificate whose purposes exceed timestamping is refused', async () => {
  const authority = await makeAuthority({ extraPurpose: true })
  const imprint = Buffer.alloc(32, 7)
  const token = await authority.mintToken({
    imprint: imprint.buffer.slice(0, 32),
    requestNonce: Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]),
  })
  await assert.rejects(
    verifyTimestampAuthority({ token, roots: [authority.rootPem], imprintInput: Buffer.from([1]) }),
    (error) => error.code === 'ANCHOR_UNTRUSTED_AUTHORITY' && /purposes/u.test(error.message),
  )
})

test('authority verification without a pinned root is a refusal, never a default store', async () => {
  await assert.rejects(
    verifyTimestampAuthority({ token: 'AAAA', roots: [], imprintInput: Buffer.from([1]) }),
    (error) => error.code === 'ANCHOR_UNTRUSTED_AUTHORITY',
  )
})

// ── The CLI, end to end and offline ─────────────────────────────────────────

test('the documented verify command runs offline: bundle in, report and state out', async () => {
  const minted = await mintBundle({})
  const directory = mkdtempSync(path.join(tmpdir(), 'pruvz-verify-'))
  const bundleFile = path.join(directory, 'verification.bundle.json')
  const rootsFile = path.join(directory, 'tsa-roots.pem')
  const stateFile = path.join(directory, 'verifier-state.json')
  writeFileSync(bundleFile, JSON.stringify(minted.bundle))
  writeFileSync(rootsFile, minted.tsaRoots.join('\n'))

  const run = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, 'bin', 'verify.mjs'),
      bundleFile,
      '--issuer',
      minted.pin.issuer,
      '--root',
      minted.pin.root,
      '--tenant',
      'tenant-demo',
      '--tsa-roots',
      rootsFile,
      '--state',
      stateFile,
      '--json',
    ],
    { encoding: 'utf8' },
  )
  assert.equal(run.status, 0, run.stderr)
  const report = JSON.parse(run.stdout)
  assert.equal(report.verdict, 'FULLY_VERIFIED')
  const state = JSON.parse(readFileSync(stateFile, 'utf8'))
  assert.equal(state.checkpoint.treeSize, minted.bundle.packet.evidence.items.length)

  // Exit code 3 distinguishes an honestly partial verdict from success.
  const partial = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, 'bin', 'verify.mjs'),
      bundleFile,
      '--issuer',
      minted.pin.issuer,
      '--root',
      minted.pin.root,
      '--tenant',
      'tenant-demo',
      '--state',
      stateFile,
    ],
    { encoding: 'utf8' },
  )
  assert.equal(partial.status, 3, partial.stderr)
  assert.match(partial.stdout, /PARTIALLY_VERIFIED/u)
})

test('the documented bundle command composes saved responses into a verifiable bundle', async () => {
  const minted = await mintBundle({})
  const directory = mkdtempSync(path.join(tmpdir(), 'pruvz-bundle-'))
  const write = (relative, value) => {
    const file = path.join(directory, relative)
    mkdirSync(path.dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify(value))
  }
  write('packet.json', minted.bundle.packet)
  for (const [evidenceId, seal] of Object.entries(minted.bundle.seals)) {
    write(path.join('seals', `${evidenceId}.json`), seal)
  }
  for (const [evidenceId, proof] of Object.entries(minted.bundle.proofs)) {
    write(path.join('proofs', `${evidenceId}.json`), proof)
  }
  minted.bundle.checkpoints.forEach((checkpoint, index) => {
    write(path.join('checkpoints', `${index + 1}.json`), checkpoint)
  })
  minted.bundle.consistencyProofs.forEach((proof, index) => {
    write(path.join('consistency', `${index + 1}.json`), proof)
  })
  minted.bundle.trustRegistry.forEach((document) => {
    write(path.join('trust-registry', `${document.manifest.registryVersion}.json`), document)
  })
  for (const [sequence, entry] of Object.entries(minted.bundle.anchors.checkpoints)) {
    write(path.join('anchors', 'checkpoints', `${sequence}.json`), entry)
  }
  for (const [version, entry] of Object.entries(minted.bundle.anchors.trustRegistry)) {
    write(path.join('anchors', 'trust-registry', `${version}.json`), entry)
  }

  const output = path.join(directory, 'verification.bundle.json')
  const composed = spawnSync(
    process.execPath,
    [path.join(repoRoot, 'bin', 'bundle.mjs'), directory, output],
    { encoding: 'utf8' },
  )
  assert.equal(composed.status, 0, composed.stderr)

  const report = await verifyBundle(JSON.parse(readFileSync(output, 'utf8')), {
    pin: minted.pin,
    expectedTenantId: 'tenant-demo',
    tsaRoots: minted.tsaRoots,
  })
  assert.equal(report.verdict, 'FULLY_VERIFIED')
})
