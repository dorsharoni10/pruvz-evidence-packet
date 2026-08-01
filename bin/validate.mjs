#!/usr/bin/env node
// Usage: npm run validate -- <packet.json> [more.json ...]
//
// Validates each file against the Pruvz Public Evidence Packet schema and
// exits 0 only when every file conforms. Structural validation only, entirely
// local: no network access, no telemetry, no account, no API key.
import { readFileSync } from 'node:fs'
import process from 'node:process'
import { SUPPORTED_VERSIONS, validatePacket } from '../lib/validator.mjs'

const files = process.argv.slice(2)

if (files.length === 0) {
  console.error('Usage: npm run validate -- <packet.json> [more.json ...]')
  console.error(`Supported packet format versions: ${SUPPORTED_VERSIONS.join(', ')}`)
  process.exit(2)
}

let failures = 0

for (const file of files) {
  let packet
  try {
    packet = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    failures += 1
    console.error(`FAIL  ${file}`)
    console.error(`      not readable as JSON: ${error.message}`)
    continue
  }

  const { valid, version, errors } = validatePacket(packet)
  if (valid) {
    console.log(`PASS  ${file}  (packet format v${version})`)
    continue
  }

  failures += 1
  console.error(`FAIL  ${file}  (validated against packet format v${version})`)
  for (const error of errors) {
    const where = error.instancePath === '' ? '(document root)' : error.instancePath
    console.error(`      ${where}: ${error.message}`)
  }
}

if (failures > 0) {
  console.error(`\n${failures} of ${files.length} file(s) failed structural validation.`)
  process.exit(1)
}

console.log(`\nAll ${files.length} file(s) conform to the published schema.`)
console.log(
  'Note: structural conformance is all this proves — not packet origin, business accuracy, or integrity.',
)
