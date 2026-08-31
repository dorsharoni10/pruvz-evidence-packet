#!/usr/bin/env node
// Usage: npm run attack-demo [-- <case-id>]
//
// Reproducible tamper demonstrations (PRUVZ-97): extracts a published
// adversarial bundle from conformance/v1/golden-vectors.json, writes it and
// the published pins to a temporary directory, runs the SAME CLI a customer
// runs (bin/verify.mjs), and shows the refusal. Nothing here is staged for
// the demo — the bundles are the frozen conformance fixtures, and the
// verifier is the shipped one.
//
// With no argument it runs the three demonstrations the README documents:
// a tampered record, a forked log history, and a substituted signing key.
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const vectors = JSON.parse(
  readFileSync(path.join(repoRoot, 'conformance', 'v1', 'golden-vectors.json'), 'utf8'),
)

const DEFAULT_DEMOS = ['mutated-evidence-field', 'checkpoint-fork-held-state', 'substituted-registry']
const requested = process.argv[2] ? [process.argv[2]] : DEFAULT_DEMOS

const workDir = mkdtempSync(path.join(tmpdir(), 'pruvz-attack-demo-'))
const tsaRootsFile = path.join(workDir, 'tsa-roots.pem')
writeFileSync(tsaRootsFile, vectors.tsaRoots.join('\n'))

const run = (args) => {
  const outcome = spawnSync(process.execPath, [path.join(repoRoot, 'bin', 'verify.mjs'), ...args], {
    encoding: 'utf8',
  })
  process.stdout.write(outcome.stdout)
  process.stdout.write(outcome.stderr)
  return outcome.status
}

let failures = 0
for (const id of requested) {
  const conformanceCase = vectors.cases.find((candidate) => candidate.id === id)
  if (conformanceCase === undefined) {
    console.error(`unknown case "${id}"; see conformance/v1/golden-vectors.json`)
    process.exit(2)
  }
  console.log(`\n=== ${conformanceCase.id} ===`)
  console.log(conformanceCase.description)

  let stateFile = null
  for (const [index, step] of conformanceCase.steps.entries()) {
    const bundleFile = path.join(workDir, `${conformanceCase.id}-${index + 1}.bundle.json`)
    writeFileSync(
      bundleFile,
      step.rawBundle !== undefined
        ? vectors.rawBundles[step.rawBundle]
        : JSON.stringify(vectors.bundles[step.bundle], null, 1),
    )
    const args = [bundleFile, '--issuer', vectors.pin.issuer, '--root', vectors.pin.root]
    if (step.options.tenant) args.push('--tenant', step.options.tenant)
    if (step.options.tsaRoots === true) args.push('--tsa-roots', tsaRootsFile)
    if (step.options.state === 'held') {
      stateFile ??= path.join(workDir, `${conformanceCase.id}.state.json`)
      args.push('--state', stateFile)
    } else if (conformanceCase.steps.length > 1) {
      stateFile = path.join(workDir, `${conformanceCase.id}.state.json`)
      args.push('--state', stateFile)
    }
    console.log(`\n$ pruvz-verify ${path.basename(bundleFile)} --issuer ${vectors.pin.issuer} --root ${vectors.pin.root.slice(0, 18)}… ${step.options.state === 'held' ? '--state held' : ''}`)
    const exitCode = run(args)
    const expected =
      step.expect.outcome === 'UNUSABLE_INPUT'
        ? 2
        : step.expect.verdict === 'FULLY_VERIFIED'
          ? 0
          : step.expect.verdict === 'PARTIALLY_VERIFIED'
            ? 3
            : 1
    if (exitCode !== expected) {
      console.error(`UNEXPECTED: exit ${exitCode}, the published expectation is ${expected}`)
      failures += 1
    } else {
      console.log(`exit ${exitCode} — exactly as published`)
    }
  }
}

process.exit(failures === 0 ? 0 : 1)
