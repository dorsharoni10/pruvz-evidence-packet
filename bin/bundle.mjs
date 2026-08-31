#!/usr/bin/env node
// Usage: npm run bundle -- <dir> [output.bundle.json]
//
// Composes a verification bundle from a directory of saved Pruvz product API
// responses — the repeatable bridge between an export session and one file
// `npm run verify` checks offline (the same role bin/compose.mjs plays for the
// packet alone). Entirely local, no network access. Expected layout, every
// part exactly the served response, nothing added, nothing removed:
//
//   <dir>/packet.json                       the composed Public Evidence Packet
//         (or action.json + evidence.json,  composed here exactly like bin/compose.mjs)
//   <dir>/seals/<evidenceId>.json           GET .../evidence/{id}/seal
//   <dir>/proofs/<evidenceId>.json          GET .../evidence/{id}/proof
//   <dir>/checkpoints/*.json                GET /api/evidence-log/checkpoints/{seq}   (optional)
//   <dir>/consistency/*.json                GET /api/evidence-log/consistency?...     (optional)
//   <dir>/trust-registry/*.json             GET /api/trust-registry?version=N — the whole chain
//   <dir>/anchors/checkpoints/<seq>.json    GET .../checkpoints/{seq}/anchors         (optional)
//   <dir>/anchors/trust-registry/<v>.json   GET /api/trust-registry/{v}/anchors       (optional)
//
// A missing optional part simply stays out of the bundle, and the verifier
// reports the corresponding dimension as absent — assembling less material
// produces a weaker verdict, never an error here.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'

import { BUNDLE_FORMAT_VERSION } from '../lib/verify.mjs'
import { SUPPORTED_VERSIONS, validatePacket } from '../lib/validator.mjs'

const [directory, outputFile] = process.argv.slice(2)
if (!directory) {
  console.error('Usage: npm run bundle -- <dir> [output.bundle.json]')
  process.exit(2)
}

const readJson = (file) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    console.error(`FAIL  ${file} is not readable as JSON: ${error.message}`)
    process.exit(1)
  }
}

const jsonFiles = (dir) =>
  existsSync(dir) ? readdirSync(dir).filter((file) => file.endsWith('.json')).sort() : []

const mapByStem = (dir) => {
  const map = {}
  for (const file of jsonFiles(dir)) {
    map[path.basename(file, '.json')] = readJson(path.join(dir, file))
  }
  return map
}

// The packet: saved as one file, or composed from the two responses exactly
// like bin/compose.mjs. A bundle may also be proof-only (no packet at all),
// which the verifier reports honestly as RETAINED_PROOF_ONLY.
let packet = null
if (existsSync(path.join(directory, 'packet.json'))) {
  packet = readJson(path.join(directory, 'packet.json'))
} else if (
  existsSync(path.join(directory, 'action.json')) &&
  existsSync(path.join(directory, 'evidence.json'))
) {
  packet = {
    packetFormatVersion: SUPPORTED_VERSIONS[0],
    action: readJson(path.join(directory, 'action.json')),
    evidence: readJson(path.join(directory, 'evidence.json')),
  }
}
if (packet !== null) {
  const { valid, version, errors } = validatePacket(packet)
  if (!valid) {
    console.error(`FAIL  the packet does not conform to format ${version}:`)
    for (const error of errors.slice(0, 10)) {
      console.error(`  ${error.instancePath} ${error.message}`)
    }
    process.exit(1)
  }
}

const registryDocuments = Object.values(mapByStem(path.join(directory, 'trust-registry'))).sort(
  (a, b) => (a?.manifest?.registryVersion ?? 0) - (b?.manifest?.registryVersion ?? 0),
)

const bundle = {
  bundleFormatVersion: BUNDLE_FORMAT_VERSION,
  packet,
  seals: mapByStem(path.join(directory, 'seals')),
  proofs: mapByStem(path.join(directory, 'proofs')),
  checkpoints: Object.values(mapByStem(path.join(directory, 'checkpoints'))),
  consistencyProofs: Object.values(mapByStem(path.join(directory, 'consistency'))),
  trustRegistry: registryDocuments.length > 0 ? registryDocuments : null,
  anchors: {
    checkpoints: mapByStem(path.join(directory, 'anchors', 'checkpoints')),
    trustRegistry: mapByStem(path.join(directory, 'anchors', 'trust-registry')),
  },
}

const output = outputFile ?? 'verification.bundle.json'
writeFileSync(output, `${JSON.stringify(bundle, null, 2)}\n`)
console.log(
  `OK    ${output}: packet ${packet === null ? 'absent (proof-only)' : 'present'}, ` +
    `${Object.keys(bundle.seals).length} seals, ${Object.keys(bundle.proofs).length} proofs, ` +
    `${bundle.checkpoints.length} checkpoints, ${registryDocuments.length} registry versions`,
)
