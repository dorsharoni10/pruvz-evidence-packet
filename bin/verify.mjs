#!/usr/bin/env node
// Usage: npm run verify -- <bundle.json> --issuer <issuer> --root <thumbprint>
//                                 [--tenant <tenantId>] [--tsa-roots <pem-file>]
//                                 [--tsa-policy <oid> ...] [--state <state.json>]
//                                 [--no-update-state] [--json]
//
// Verifies one exported verification bundle completely offline and prints the
// dimensional assurance report. The trust anchor (--issuer and --root) is the
// pin established out of band (docs/TRUST-REGISTRY.md section 4) and is
// mandatory: there is no pinless mode, and nothing is ever fetched from a
// Pruvz deployment or website. Exit codes: 0 FULLY_VERIFIED, 3
// PARTIALLY_VERIFIED, 1 NOT_VERIFIED, 2 usage or unreadable input.
//
// --state names a JSON file holding what this verifier accepted before (the
// registry version and checkpoint it saw). When given, rollback and fork
// presentations become refusals instead of surprises, and the file is updated
// after a run unless --no-update-state. A first run writes the initial state. A
// file that is not exactly what a previous run returned is refused as unusable
// input (STATE_MALFORMED) rather than reinterpreted, and only checkpoints
// verified under the pinned registry are ever written into it.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'

import { verifyBundle } from '../lib/verify.mjs'
import { assertUniqueMembers } from '../lib/json-guard.mjs'

const usage = () => {
  console.error(
    'Usage: npm run verify -- <bundle.json> --issuer <issuer> --root <thumbprint>\n' +
      '                                [--tenant <tenantId>] [--tsa-roots <pem-file>]\n' +
      '                                [--tsa-policy <oid> ...] [--state <state.json>]\n' +
      '                                [--no-update-state] [--json]',
  )
  process.exit(2)
}

const args = process.argv.slice(2)
let bundleFile = null
let issuer = null
let root = null
let tenant = null
let tsaRootsFile = null
const tsaPolicyOids = []
let stateFile = null
let updateState = true
let asJson = false

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index]
  const next = () => {
    index += 1
    if (index >= args.length) usage()
    return args[index]
  }
  if (arg === '--issuer') issuer = next()
  else if (arg === '--root') root = next()
  else if (arg === '--tenant') tenant = next()
  else if (arg === '--tsa-roots') tsaRootsFile = next()
  else if (arg === '--tsa-policy') tsaPolicyOids.push(next())
  else if (arg === '--state') stateFile = next()
  else if (arg === '--no-update-state') updateState = false
  else if (arg === '--json') asJson = true
  else if (arg.startsWith('--')) usage()
  else if (bundleFile === null) bundleFile = arg
  else usage()
}

if (bundleFile === null || issuer === null || root === null) usage()

const readJson = (file, what) => {
  try {
    const text = readFileSync(file, 'utf8')
    // One byte string that parses as two different documents (duplicate
    // member names) is unusable input at a trust boundary, not a nuance —
    // conformance/v1 `duplicate-member-refused`.
    assertUniqueMembers(text)
    return JSON.parse(text)
  } catch (error) {
    console.error(`FAIL  ${what} ${file} is not readable as JSON: ${error.message}`)
    process.exit(2)
  }
}

const bundle = readJson(bundleFile, 'bundle')
const state = stateFile !== null && existsSync(stateFile) ? readJson(stateFile, 'state') : null

let tsaRoots = null
if (tsaRootsFile !== null) {
  const pem = readFileSync(tsaRootsFile, 'utf8')
  tsaRoots = [...pem.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(
    (match) => match[0],
  )
  if (tsaRoots.length === 0) {
    console.error(`FAIL  ${tsaRootsFile} contains no PEM certificates`)
    process.exit(2)
  }
}

let report
try {
  report = await verifyBundle(bundle, {
    pin: { issuer, root },
    expectedTenantId: tenant,
    tsaRoots,
    tsaPolicyOids: tsaPolicyOids.length > 0 ? tsaPolicyOids : null,
    state,
  })
} catch (error) {
  console.error(`FAIL  ${error.code ?? 'ERROR'}  ${error.message}`)
  process.exit(2)
}

if (stateFile !== null && updateState && report.verdict !== 'NOT_VERIFIED') {
  writeFileSync(stateFile, `${JSON.stringify(report.state, null, 2)}\n`)
}

if (asJson) {
  console.log(JSON.stringify(report, null, 2))
} else {
  console.log(`Verdict: ${report.verdict}`)
  console.log('')
  console.log('Dimensions:')
  for (const [name, dimension] of Object.entries(report.dimensions)) {
    console.log(`  ${name.padEnd(18)} ${dimension.status}`)
  }
  if (report.evidence.length > 0) {
    console.log('')
    console.log('Evidence:')
    for (const entry of report.evidence) {
      console.log(
        `  ${String(entry.sequence ?? '?').padStart(3)}  ${entry.evidenceId}  ` +
          `commitment=${entry.commitment}  seal=${entry.seal?.status}  inclusion=${entry.inclusion?.status}`,
      )
    }
  }
  if (report.reasonCodes.length > 0) {
    console.log('')
    console.log(`Reason codes: ${report.reasonCodes.join(', ')}`)
  }
  for (const explanation of report.explanations) {
    console.log(`  - [${explanation.code}] ${explanation.message}`)
  }
}

process.exit(report.verdict === 'FULLY_VERIFIED' ? 0 : report.verdict === 'PARTIALLY_VERIFIED' ? 3 : 1)
