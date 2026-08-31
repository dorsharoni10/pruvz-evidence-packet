#!/usr/bin/env node
// The Node conformance harness (PRUVZ-97).
//
// Replays every published vector — the four layer vector packs, the
// verifier/v1 golden cases and the conformance/v1 adversarial suite — through
// the reference implementation in lib/, and emits one normalized results
// document. It NEVER reads a vector's expectation to produce an answer: every
// value it emits is computed from vector inputs alone, and the comparison
// against the expectations (and against the .NET and Python harnesses) is the
// separate bin/conformance-compare.mjs step.
//
// Usage: node conformance/node/run.mjs <out-file.json>
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import {
  canonicalDecimal,
  canonicalTimestamp,
  canonicalize,
  commitmentDigest,
  evidenceItemDocument,
  evidencePacketDocument,
  requireSupported,
} from '../../lib/canonical.mjs'
import {
  acceptChain,
  jwkThumbprint,
  manifestInput,
  verifyManifest,
  verifySeal,
} from '../../lib/trust-registry.mjs'
import {
  acceptCheckpoint,
  checkpointSigningInput,
  leafHashOf,
  leafInput,
  sealLeafHash,
  treeHead,
  validateCheckpointDocument,
  verifyCheckpoint,
  verifyConsistency,
  verifyInclusion,
} from '../../lib/evidence-log.mjs'
import { anchorImprint, anchorInput, verifyAnchorBinding } from '../../lib/anchoring.mjs'
import { embeddedCertificates, verifyTimestampAuthority } from '../../lib/anchor-authority.mjs'
import { verifyBundle } from '../../lib/verify.mjs'
import { DuplicateMemberError, assertUniqueMembers } from '../../lib/json-guard.mjs'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const loadVectors = (name) =>
  JSON.parse(readFileSync(path.join(repoRoot, name, 'v1', 'golden-vectors.json'), 'utf8'))

const commitmentVectors = loadVectors('commitment')
const registryVectors = loadVectors('trust-registry')
const logVectors = loadVectors('evidence-log')
const anchoringVectors = loadVectors('anchoring')
const verifierVectors = loadVectors('verifier')
const conformanceVectors = loadVectors('conformance')

const clone = (value) => JSON.parse(JSON.stringify(value))
const sha256hex = (bytes) => createHash('sha256').update(bytes).digest('hex')
const sorted = (list) => [...list].sort()

/** The refusal code of a callable, or null when it does not refuse. */
const codeOf = (fn) => {
  try {
    fn()
    return null
  } catch (error) {
    return error.code ?? error.name
  }
}

const normalizeReport = (report) => ({
  outcome: 'REPORT',
  verdict: report.verdict,
  reasonCodes: sorted(report.reasonCodes),
  dimensions: Object.fromEntries(
    Object.entries(report.dimensions).map(([name, dimension]) => [name, dimension.status ?? 'COMPOSITE']),
  ),
  state: clone(report.state),
})

// ── commitment/v1 ───────────────────────────────────────────────────────────

const runCommitment = () => {
  const out = { decimals: [], timestamps: [], canonicalization: {}, commitments: {}, rejected: {} }
  for (const vector of commitmentVectors.decimals) {
    out.decimals.push(canonicalDecimal(vector.input))
  }
  for (const vector of commitmentVectors.timestamps) {
    out.timestamps.push(canonicalTimestamp(vector.input))
  }
  for (const vector of commitmentVectors.canonicalization) {
    const document = vector.documentJson !== undefined ? JSON.parse(vector.documentJson) : vector.document
    out.canonicalization[vector.id] = canonicalize(document).toString('utf8')
  }
  for (const vector of commitmentVectors.commitments) {
    const document =
      vector.kind === 'evidence-item'
        ? evidenceItemDocument(vector.source)
        : evidencePacketDocument(vector.source)
    out.commitments[vector.id] = {
      canonical: canonicalize(document).toString('utf8'),
      digest: commitmentDigest(vector.kind, document),
    }
  }
  for (const vector of commitmentVectors.rejected) {
    out.rejected[vector.id] = codeOf(() => rejectOne(vector))
  }
  return out
}

/** Runs one rejected-vector input through the layer the vector names. */
const rejectOne = (vector) => {
  const document = vector.documentJson !== undefined ? JSON.parse(vector.documentJson) : vector.document
  switch (vector.layer) {
    case 'decimal':
      return canonicalDecimal(vector.input)
    case 'timestamp':
      return canonicalTimestamp(vector.input)
    case 'canonicalization':
      return canonicalize(document)
    case 'commitment':
      return commitmentDigest(vector.kind, document)
    case 'digest':
      return commitmentDigest(vector.kind, document, vector.suite)
    case 'supported':
      return requireSupported(vector.commitmentVersion, vector.suite)
    case 'evidence-item-document':
      return evidenceItemDocument(vector.source)
    case 'evidence-packet-document':
      return evidencePacketDocument(vector.source)
    default:
      throw new Error(`unknown rejected-vector layer "${vector.layer}"`)
  }
}

// ── trust-registry/v1 ───────────────────────────────────────────────────────

const runTrustRegistry = () => {
  const out = { thumbprints: {}, digests: {}, chainCases: {}, refusalCases: {}, sealCases: {} }
  for (const vector of registryVectors.thumbprints) {
    out.thumbprints[vector.id] = jwkThumbprint(vector.jwk)
  }
  const allDocuments = { ...registryVectors.documents, ...registryVectors.badDocuments }
  for (const [id] of Object.entries(registryVectors.digests)) {
    const document = allDocuments[id]
    out.digests[id] = `sha256:${sha256hex(manifestInput(document.manifest))}`
  }
  for (const scenario of registryVectors.chainCases) {
    const pin = 'pinOverride' in scenario ? scenario.pinOverride : registryVectors.pin
    let outcome
    try {
      let state = null
      for (const id of scenario.establish) {
        state = acceptChain([allDocuments[id]], { pin: registryVectors.pin, state }).state
      }
      const accepted = acceptChain(
        scenario.attempt.map((id) => allDocuments[id]),
        { pin, state },
      )
      outcome = {
        outcome: 'ACCEPT',
        registryVersion: accepted.state.registryVersion,
        digest: accepted.state.digest,
      }
    } catch (error) {
      outcome = { outcome: 'REFUSE', code: error.code ?? error.name }
    }
    out.chainCases[scenario.id] = outcome
  }
  for (const scenario of registryVectors.refusalCases) {
    out.refusalCases[scenario.id] = codeOf(() =>
      verifyManifest(allDocuments[scenario.document], { pin: registryVectors.pin }),
    )
  }
  for (const scenario of registryVectors.sealCases) {
    const { manifest } = verifyManifest(registryVectors.documents[scenario.registry], {
      pin: registryVectors.pin,
    })
    const result = verifySeal({
      seal: registryVectors.seals[scenario.seal],
      manifest,
      expectedSubject: registryVectors.subjects[scenario.subject],
      expectedCommitmentDigest:
        scenario.commitmentDigest === null
          ? null
          : registryVectors.expectedCommitmentDigests[scenario.commitmentDigest],
    })
    out.sealCases[scenario.id] = {
      verdict: result.verdict,
      reasonCodes: sorted(result.reasonCodes),
      dimensions: result.dimensions,
    }
  }
  return out
}

// ── evidence-log/v1 ─────────────────────────────────────────────────────────

const runEvidenceLog = () => {
  const out = {
    rfc6962LeafHashes: [],
    rfc6962RootsBySize: [],
    leafInputSha256: {},
    leafHashes: [],
    treeRootsBySize: [],
    inclusion: [],
    consistency: [],
    checkpointSigningInputSha256: {},
    acceptanceChain: [],
    refusals: {},
  }
  const known = logVectors.rfc6962KnownAnswers
  const knownHashes = known.leafDataHex.map((hex) => leafHashOf(Buffer.from(hex, 'hex')).toString('hex'))
  out.rfc6962LeafHashes = knownHashes
  out.rfc6962RootsBySize = knownHashes.map((_, index) => treeHead(knownHashes.slice(0, index + 1)))

  for (const [id, seal] of Object.entries(logVectors.seals)) {
    out.leafInputSha256[id] = sha256hex(leafInput(seal))
    out.leafHashes.push(sealLeafHash(seal))
  }
  out.treeRootsBySize = out.leafHashes.map((_, index) => treeHead(out.leafHashes.slice(0, index + 1)))

  for (const vector of logVectors.tree.inclusion) {
    out.inclusion.push(
      codeOf(() =>
        verifyInclusion({
          leafHash: out.leafHashes[vector.leafIndex],
          leafIndex: vector.leafIndex,
          treeSize: vector.treeSize,
          path: vector.path,
          rootHash: out.treeRootsBySize[vector.treeSize - 1],
        }),
      ) ?? 'VERIFIED',
    )
  }
  for (const vector of logVectors.tree.consistency) {
    out.consistency.push(
      codeOf(() =>
        verifyConsistency({
          fromSize: vector.fromSize,
          fromRootHash: out.treeRootsBySize[vector.fromSize - 1],
          toSize: vector.toSize,
          toRootHash: out.treeRootsBySize[vector.toSize - 1],
          proof: vector.proof,
        }),
      ) ?? 'VERIFIED',
    )
  }

  for (const [id, entry] of Object.entries(logVectors.checkpoints)) {
    verifyCheckpoint({ checkpoint: entry.checkpoint, signature: entry.signature, jwk: logVectors.signingKey.jwk })
    out.checkpointSigningInputSha256[id] = sha256hex(checkpointSigningInput(entry.checkpoint))
  }

  let accepted = null
  for (const step of logVectors.acceptanceChain.steps) {
    const { checkpoint } = logVectors.checkpoints[step.candidate]
    accepted = acceptCheckpoint({ accepted, candidate: checkpoint, consistencyProof: step.consistencyProof })
    out.acceptanceChain.push({ candidate: step.candidate, treeSize: accepted.treeSize, rootHash: accepted.rootHash })
  }

  for (const refusal of logVectors.refusals) {
    out.refusals[refusal.id] = codeOf(() => {
      switch (refusal.kind) {
        case 'validateCheckpoint':
          return validateCheckpointDocument(refusal.document)
        case 'leaf':
          return leafInput(refusal.seal)
        case 'inclusion':
          return verifyInclusion({
            leafHash: refusal.tamperedSeal ? sealLeafHash(refusal.tamperedSeal) : refusal.leafHash,
            leafIndex: refusal.leafIndex,
            treeSize: refusal.treeSize,
            path: refusal.path,
            rootHash: refusal.rootHashHex,
          })
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
            jwk: refusal.jwk ?? logVectors.signingKey.jwk,
          })
        case 'acceptance':
          return acceptCheckpoint({
            accepted: refusal.accepted,
            candidate: refusal.candidate,
            consistencyProof: refusal.consistencyProof,
          })
        default:
          throw new Error(`unknown refusal kind "${refusal.kind}"`)
      }
    })
  }
  return out
}

// ── anchoring/v1 ────────────────────────────────────────────────────────────

const resolveToken = (token) =>
  token.startsWith('@') ? anchoringVectors.receipts[token.slice(1)] : token

const materializeRecord = (record) => {
  const out = clone(record)
  if (out.receipt?.token?.startsWith('@')) {
    out.receipt = { ...out.receipt, token: resolveToken(out.receipt.token) }
  }
  return out
}

const runAnchoring = async () => {
  const out = { deterministic: {}, bindingCases: {}, refusals: {}, runtimeDivergence: {} }
  for (const vector of anchoringVectors.deterministic) {
    const subject = anchoringVectors.subjects[vector.subjectRef]
    const kind = subject.checkpoint !== undefined ? 'log-checkpoint' : 'trust-registry'
    const nonce = Buffer.from(vector.blindingNonce, 'base64url')
    const input = anchorInput(kind, nonce, subject)
    out.deterministic[vector.id] = {
      anchorInputLength: input.length,
      anchorInputSha256: sha256hex(input),
      imprint: anchorImprint(kind, nonce, subject).toString('hex'),
    }
  }
  for (const vector of anchoringVectors.bindingCases) {
    const record = materializeRecord(vector.record)
    const subject = anchoringVectors.subjects[vector.subjectRef]
    const binding = verifyAnchorBinding({ record, subject })
    out.bindingCases[vector.id] = {
      genTime: binding.genTime,
      policyOid: binding.policyOid,
      imprint: binding.imprint,
    }
  }
  for (const vector of anchoringVectors.refusals) {
    const record = materializeRecord(vector.record)
    const subject = anchoringVectors.subjects[vector.subjectRef]
    out.refusals[vector.id] = codeOf(() => verifyAnchorBinding({ record, subject }))
  }
  for (const vector of anchoringVectors.runtimeDivergence) {
    const record = materializeRecord(vector.record)
    const subject = anchoringVectors.subjects[vector.subjectRef]
    const binds = codeOf(() => verifyAnchorBinding({ record, subject })) === null
    // Half two, against the token's own embedded chain root as the pin — the
    // replay is about the signature, not about which authority is trusted.
    const chain = embeddedCertificates(record.receipt.token)
    let halfTwoCode = null
    try {
      await verifyTimestampAuthority({
        token: record.receipt.token,
        roots: [chain[chain.length - 1]],
        imprintInput: anchorInput(record.subject.kind, record.blindingNonce, subject),
      })
    } catch (error) {
      halfTwoCode = error.code ?? error.name
    }
    out.runtimeDivergence[vector.id] = { binds, halfTwoCode }
  }
  return out
}

// ── verifier/v1 and conformance/v1 ──────────────────────────────────────────

const runVerifierCases = async () => {
  const out = {}
  for (const goldenCase of verifierVectors.cases) {
    const report = await verifyBundle(clone(verifierVectors.bundles[goldenCase.bundle]), {
      pin: goldenCase.options.pinRootOverride
        ? { issuer: verifierVectors.pin.issuer, root: goldenCase.options.pinRootOverride }
        : verifierVectors.pin,
      expectedTenantId: goldenCase.options.tenant ?? null,
      tsaRoots: goldenCase.options.tsaRoots ? verifierVectors.tsaRoots : null,
    })
    out[goldenCase.id] = normalizeReport(report)
  }
  return out
}

const runConformanceCases = async () => {
  const out = {}
  for (const conformanceCase of conformanceVectors.cases) {
    const results = []
    let heldState = null
    for (const step of conformanceCase.steps) {
      const rawText =
        step.rawBundle !== undefined
          ? conformanceVectors.rawBundles[step.rawBundle]
          : JSON.stringify(conformanceVectors.bundles[step.bundle])
      let bundle
      try {
        assertUniqueMembers(rawText)
        bundle = JSON.parse(rawText)
      } catch (error) {
        if (!(error instanceof DuplicateMemberError) && !(error instanceof SyntaxError)) throw error
        results.push({ outcome: 'UNUSABLE_INPUT' })
        continue
      }
      try {
        const report = await verifyBundle(bundle, {
          pin: conformanceVectors.pin,
          expectedTenantId: step.options.tenant ?? null,
          tsaRoots:
            step.options.tsaRoots === true
              ? conformanceVectors.tsaRoots
              : step.options.tsaRoots === 'wrong'
                ? conformanceVectors.wrongTsaRoots
                : null,
          state: step.options.state === 'held' ? heldState : null,
        })
        heldState = clone(report.state)
        results.push(normalizeReport(report))
      } catch (error) {
        // Only the verifier's own coded refusals read as unusable input — a
        // TypeError is a harness or implementation bug and must crash the
        // run, not pass a case whose expectation happens to be a refusal.
        if (typeof error?.code !== 'string') throw error
        results.push({ outcome: 'UNUSABLE_INPUT' })
      }
    }
    out[conformanceCase.id] = results
  }
  return out
}

// ── Emit ────────────────────────────────────────────────────────────────────

const outFile = process.argv[2]
if (!outFile) {
  console.error('Usage: node conformance/node/run.mjs <out-file.json>')
  process.exit(2)
}

const results = {
  harnessResultsVersion: '1',
  runtime: 'node',
  layers: {
    commitment: runCommitment(),
    trustRegistry: runTrustRegistry(),
    evidenceLog: runEvidenceLog(),
    anchoring: await runAnchoring(),
  },
  verifierV1: await runVerifierCases(),
  conformance: await runConformanceCases(),
}

// The results directory is generated output and is not in git, so a fresh
// clone has to create it before the first harness writes into it.
mkdirSync(path.dirname(path.resolve(outFile)), { recursive: true })
writeFileSync(outFile, `${JSON.stringify(results, null, 1)}\n`)
console.log(`node harness: wrote ${outFile}`)
