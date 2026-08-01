#!/usr/bin/env node
// Usage: npm run compose -- <action.json> <evidence.json> [output.packet.json]
//
// Composes a Public Evidence Packet from the two saved responses of the Pruvz
// product API — the action details view (GET /api/actions/{actionId}) and the
// evidence timeline (GET /api/actions/{actionId}/evidence) — exactly as this
// repository defines the packet: the two responses under a packetFormatVersion
// envelope, nothing added, nothing removed.
//
// The composed packet is validated (schema + packet-level consistency) before
// it is written; composition fails if the product output and this contract
// disagree, which is the point: this tool is the repeatable bridge between a
// live demo run and a conforming packet. Entirely local, no network access.
import { readFileSync, writeFileSync } from 'node:fs'
import process from 'node:process'
import { SUPPORTED_VERSIONS, validatePacket } from '../lib/validator.mjs'

const [actionFile, evidenceFile, outputFile] = process.argv.slice(2)

if (!actionFile || !evidenceFile) {
  console.error('Usage: npm run compose -- <action.json> <evidence.json> [output.packet.json]')
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

const packet = {
  packetFormatVersion: SUPPORTED_VERSIONS[0],
  action: readJson(actionFile),
  evidence: readJson(evidenceFile),
}

const { valid, version, errors } = validatePacket(packet)
if (!valid) {
  console.error(
    `FAIL  the composed packet does not conform to packet format v${version} — `
      + 'either the inputs are not the two documented API responses, or the '
      + 'product contract and this schema release have diverged (which is a bug worth reporting):',
  )
  for (const error of errors) {
    const where = error.instancePath === '' ? '(document root)' : error.instancePath
    console.error(`      ${where}: ${error.message}`)
  }
  process.exit(1)
}

const rendered = JSON.stringify(packet, null, 2) + '\n'
if (outputFile) {
  writeFileSync(outputFile, rendered)
  console.log(`PASS  wrote conforming packet (format v${version}) to ${outputFile}`)
} else {
  process.stdout.write(rendered)
}
