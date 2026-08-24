// Proves the composer builds a conforming packet from the two documented API
// responses and refuses inputs that do not belong together — the repeatable
// bridge between a live product run and a packet in this format.
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.join(here, '..')
const cli = path.join(repoRoot, 'bin', 'compose.mjs')
const validDir = path.join(repoRoot, 'examples', 'valid')

const loadPacket = (name) =>
  JSON.parse(readFileSync(path.join(validDir, name), 'utf8'))

test('composing the two API responses reproduces the packet exactly', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pruvz-compose-'))
  try {
    // Decompose a known-good packet of the newest format into the two
    // documented API responses… (compose stamps the newest format version, so
    // only a newest-format example can round-trip byte-equivalently)
    const original = loadPacket('reverified-confirmed.packet.json')
    const actionFile = path.join(dir, 'action.json')
    const evidenceFile = path.join(dir, 'evidence.json')
    const outFile = path.join(dir, 'out.packet.json')
    writeFileSync(actionFile, JSON.stringify(original.action))
    writeFileSync(evidenceFile, JSON.stringify(original.evidence))

    // …and composition must rebuild it byte-equivalently (as JSON values).
    const run = spawnSync(process.execPath, [cli, actionFile, evidenceFile, outFile], {
      encoding: 'utf8',
    })
    assert.equal(run.status, 0, `expected exit 0, got ${run.status}: ${run.stderr}`)

    const composed = JSON.parse(readFileSync(outFile, 'utf8'))
    assert.deepEqual(composed, original)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('composing responses of two different actions is refused', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pruvz-compose-'))
  try {
    const verified = loadPacket('reverified-confirmed.packet.json')
    const mismatch = loadPacket('reverified-mismatch.packet.json')
    const actionFile = path.join(dir, 'action.json')
    const evidenceFile = path.join(dir, 'evidence.json')
    writeFileSync(actionFile, JSON.stringify(verified.action))
    writeFileSync(evidenceFile, JSON.stringify(mismatch.evidence))

    const run = spawnSync(process.execPath, [cli, actionFile, evidenceFile], {
      encoding: 'utf8',
    })
    assert.equal(run.status, 1, 'mismatched inputs must fail composition')
    assert.match(run.stderr, /must equal \/action\/actionId/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
