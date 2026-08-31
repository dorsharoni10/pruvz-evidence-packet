#!/usr/bin/env node
// The conformance comparison (PRUVZ-97): the one place expectations are read.
//
// Each runtime harness (Node, .NET, Python) replays every published vector
// and emits a normalized results document computed from vector INPUTS alone.
// This script then asserts, for every published case:
//
//   1. runtime == golden expected result   — for each runtime given;
//   2. runtime == runtime                  — all runtimes byte-agree on the
//                                            entire normalized document.
//
// Two implementations agreeing on the same mistake is exactly the failure
// mode rule 1 exists to catch; a hidden assumption shared with the vectors
// is what rule 2 exists to catch. Exit code 0 only when both hold everywhere.
//
// Usage: node bin/conformance-compare.mjs <results.json> [<results.json> ...]
import { readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const loadVectors = (name) =>
  JSON.parse(readFileSync(path.join(repoRoot, name, 'v1', 'golden-vectors.json'), 'utf8'))

const commitmentVectors = loadVectors('commitment')
const registryVectors = loadVectors('trust-registry')
const logVectors = loadVectors('evidence-log')
const anchoringVectors = loadVectors('anchoring')
const verifierVectors = loadVectors('verifier')
const conformanceVectors = loadVectors('conformance')

// Documented erratum (docs/VERIFIER.md): verifier/v1 pinned a reason code
// outside the anchoring layer's closed vocabulary; every replay substitutes
// the accurate code. conformance/v1 pins the corrected code directly.
const VERIFIER_V1_ERRATA = { ANCHOR_RECEIPT_SIGNATURE_INVALID: 'ANCHOR_SIGNATURE_INVALID' }
const sorted = (list) => [...list].sort()
const withErrata = (codes) => sorted(codes.map((code) => VERIFIER_V1_ERRATA[code] ?? code))

const failures = []
const check = (where, actual, expected) => {
  if (!isDeepStrictEqual(actual, expected)) {
    failures.push(
      `${where}\n    expected: ${JSON.stringify(expected)}\n    actual:   ${JSON.stringify(actual)}`,
    )
  }
}

// ── runtime == golden expected ──────────────────────────────────────────────

const compareToExpected = (results) => {
  const who = results.runtime
  const at = (label) => `${who}: ${label}`
  const layers = results.layers
  check(at('harnessResultsVersion'), results.harnessResultsVersion, '1')

  // commitment/v1
  check(at('commitment.decimals'), layers.commitment.decimals, commitmentVectors.decimals.map((vector) => vector.canonical))
  check(at('commitment.timestamps'), layers.commitment.timestamps, commitmentVectors.timestamps.map((vector) => vector.canonical))
  for (const vector of commitmentVectors.canonicalization) {
    check(at(`commitment.canonicalization.${vector.id}`), layers.commitment.canonicalization[vector.id], vector.canonical)
  }
  for (const vector of commitmentVectors.commitments) {
    check(at(`commitment.commitments.${vector.id}`), layers.commitment.commitments[vector.id], {
      canonical: vector.canonical,
      digest: vector.digest,
    })
  }
  for (const vector of commitmentVectors.rejected) {
    check(at(`commitment.rejected.${vector.id}`), layers.commitment.rejected[vector.id], vector.code)
  }

  // trust-registry/v1
  for (const vector of registryVectors.thumbprints) {
    check(at(`trustRegistry.thumbprints.${vector.id}`), layers.trustRegistry.thumbprints[vector.id], vector.thumbprint)
  }
  check(at('trustRegistry.digests'), layers.trustRegistry.digests, registryVectors.digests)
  for (const scenario of registryVectors.chainCases) {
    const expected =
      scenario.expect === 'ACCEPT'
        ? { outcome: 'ACCEPT', registryVersion: scenario.expectedRegistryVersion, digest: scenario.expectedDigest }
        : { outcome: 'REFUSE', code: scenario.expect }
    check(at(`trustRegistry.chainCases.${scenario.id}`), layers.trustRegistry.chainCases[scenario.id], expected)
  }
  for (const scenario of registryVectors.refusalCases) {
    check(at(`trustRegistry.refusalCases.${scenario.id}`), layers.trustRegistry.refusalCases[scenario.id], scenario.expect)
  }
  for (const scenario of registryVectors.sealCases) {
    const actual = layers.trustRegistry.sealCases[scenario.id]
    check(at(`trustRegistry.sealCases.${scenario.id}.verdict`), actual?.verdict, scenario.expectedVerdict)
    check(at(`trustRegistry.sealCases.${scenario.id}.reasonCodes`), actual?.reasonCodes, sorted(scenario.expectedReasonCodes))
    if (scenario.expectedDimensions !== undefined) {
      // Not every published case pins dimensions; where one does not, the
      // cross-runtime comparison still covers them in full.
      check(at(`trustRegistry.sealCases.${scenario.id}.dimensions`), actual?.dimensions, scenario.expectedDimensions)
    }
  }

  // evidence-log/v1
  check(at('evidenceLog.rfc6962LeafHashes'), layers.evidenceLog.rfc6962LeafHashes, logVectors.rfc6962KnownAnswers.leafHashes)
  check(at('evidenceLog.rfc6962RootsBySize'), layers.evidenceLog.rfc6962RootsBySize, logVectors.rfc6962KnownAnswers.rootsBySize)
  check(at('evidenceLog.leafInputSha256'), layers.evidenceLog.leafInputSha256, logVectors.leafInputSha256)
  check(at('evidenceLog.leafHashes'), layers.evidenceLog.leafHashes, logVectors.leafHashes)
  check(at('evidenceLog.treeRootsBySize'), layers.evidenceLog.treeRootsBySize, logVectors.tree.rootsBySize)
  check(at('evidenceLog.inclusion'), layers.evidenceLog.inclusion, logVectors.tree.inclusion.map(() => 'VERIFIED'))
  check(at('evidenceLog.consistency'), layers.evidenceLog.consistency, logVectors.tree.consistency.map(() => 'VERIFIED'))
  check(
    at('evidenceLog.checkpointSigningInputSha256'),
    layers.evidenceLog.checkpointSigningInputSha256,
    logVectors.checkpointSigningInputSha256,
  )
  check(
    at('evidenceLog.acceptanceChain'),
    layers.evidenceLog.acceptanceChain,
    logVectors.acceptanceChain.steps.map((step) => {
      const { checkpoint } = logVectors.checkpoints[step.candidate]
      return { candidate: step.candidate, treeSize: checkpoint.treeSize, rootHash: checkpoint.rootHash }
    }),
  )
  for (const refusal of logVectors.refusals) {
    check(at(`evidenceLog.refusals.${refusal.id}`), layers.evidenceLog.refusals[refusal.id], refusal.expect)
  }

  // anchoring/v1
  for (const vector of anchoringVectors.deterministic) {
    check(at(`anchoring.deterministic.${vector.id}`), layers.anchoring.deterministic[vector.id], {
      anchorInputLength: vector.anchorInputLength,
      anchorInputSha256: vector.anchorInputSha256,
      imprint: vector.imprint,
    })
  }
  for (const vector of anchoringVectors.bindingCases) {
    check(at(`anchoring.bindingCases.${vector.id}`), layers.anchoring.bindingCases[vector.id], {
      genTime: vector.expect.genTime,
      policyOid: vector.expect.policyOid,
      imprint: vector.expect.imprint,
    })
  }
  for (const vector of anchoringVectors.refusals) {
    check(at(`anchoring.refusals.${vector.id}`), layers.anchoring.refusals[vector.id], vector.expect)
  }
  for (const vector of anchoringVectors.runtimeDivergence) {
    const actual = layers.anchoring.runtimeDivergence[vector.id]
    check(at(`anchoring.runtimeDivergence.${vector.id}.binds`), actual?.binds, vector.halfOne.accepts)
    const acceptable = [vector.halfTwo.expect, ...(vector.halfTwo.alsoAcceptable ?? [])]
    if (!acceptable.includes(actual?.halfTwoCode)) {
      failures.push(
        `${who}: anchoring.runtimeDivergence.${vector.id}.halfTwoCode\n    expected one of: ` +
          `${JSON.stringify(acceptable)}\n    actual:   ${JSON.stringify(actual?.halfTwoCode)}`,
      )
    }
  }

  // verifier/v1 — verdict, reason codes (with the documented erratum) and
  // dimension statuses; the returned state is compared across runtimes only.
  for (const goldenCase of verifierVectors.cases) {
    const actual = results.verifierV1[goldenCase.id]
    check(at(`verifierV1.${goldenCase.id}.verdict`), actual?.verdict, goldenCase.expect.verdict)
    check(at(`verifierV1.${goldenCase.id}.reasonCodes`), actual?.reasonCodes, withErrata(goldenCase.expect.reasonCodes))
    check(at(`verifierV1.${goldenCase.id}.dimensions`), actual?.dimensions, goldenCase.expect.dimensions)
  }

  // conformance/v1 — the full frozen expectation, state included.
  for (const conformanceCase of conformanceVectors.cases) {
    const actualSteps = results.conformance[conformanceCase.id] ?? []
    check(at(`conformance.${conformanceCase.id}.stepCount`), actualSteps.length, conformanceCase.steps.length)
    conformanceCase.steps.forEach((step, index) => {
      const label = conformanceCase.steps.length > 1 ? `${conformanceCase.id}#${index + 1}` : conformanceCase.id
      const expected =
        step.expect.outcome === 'UNUSABLE_INPUT'
          ? { outcome: 'UNUSABLE_INPUT' }
          : {
              outcome: 'REPORT',
              verdict: step.expect.verdict,
              reasonCodes: sorted(step.expect.reasonCodes),
              dimensions: step.expect.dimensions,
              state: step.expect.state,
            }
      check(at(`conformance.${label}`), actualSteps[index], expected)
    })
  }
}

// ── runtime == runtime ──────────────────────────────────────────────────────

const compareAcrossRuntimes = (allResults) => {
  const [reference, ...rest] = allResults
  for (const other of rest) {
    const strip = ({ runtime, ...body }) => body
    if (!isDeepStrictEqual(strip(reference), strip(other))) {
      // Locate the first divergence for a readable failure.
      const walk = (a, b, trail) => {
        if (isDeepStrictEqual(a, b)) return null
        if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
          return `${trail}\n    ${reference.runtime}: ${JSON.stringify(a)}\n    ${other.runtime}: ${JSON.stringify(b)}`
        }
        const keys = new Set([...Object.keys(a), ...Object.keys(b)])
        for (const key of keys) {
          const found = walk(a[key], b[key], `${trail}.${key}`)
          if (found !== null) return found
        }
        return `${trail}: differ`
      }
      failures.push(`cross-runtime ${reference.runtime} != ${other.runtime}: ${walk(strip(reference), strip(other), '$')}`)
    }
  }
}

// ── Run ─────────────────────────────────────────────────────────────────────

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('Usage: node bin/conformance-compare.mjs <results.json> [<results.json> ...]')
  process.exit(2)
}

const allResults = files.map((file) => JSON.parse(readFileSync(file, 'utf8')))
for (const results of allResults) {
  try {
    compareToExpected(results)
  } catch (error) {
    // A results document missing a whole section reads as a failure of that
    // runtime, never as a crash of the comparison.
    failures.push(`${results.runtime ?? 'unnamed runtime'}: results document is not comparable: ${error.message}`)
  }
}
if (allResults.length > 1) {
  compareAcrossRuntimes(allResults)
}

const runtimes = allResults.map((results) => results.runtime).join(', ')
if (failures.length > 0) {
  console.error(`CONFORMANCE FAILURES (${failures.length}) across [${runtimes}]:`)
  for (const failure of failures) {
    console.error(`  - ${failure}`)
  }
  process.exit(1)
}
console.log(
  `conformance: [${runtimes}] agree with the golden expectations` +
    (allResults.length > 1 ? ' and with each other' : '') +
    ` (${conformanceVectors.cases.length} adversarial cases, ${verifierVectors.cases.length} verifier cases, 4 layer packs)`,
)
