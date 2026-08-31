// The adversarial conformance suite (PRUVZ-97), replayed through the Node
// implementation as part of the ordinary test run: every published case must
// produce exactly the frozen verdict, reason codes, dimension statuses and
// returned state. The full three-runtime comparison (Node, .NET, Python) is
// `npm run conformance:all` and runs in CI; this file is the standing guard
// that keeps the Node implementation conformant between those runs.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { verifyBundle } from '../lib/verify.mjs'
import { DuplicateMemberError, assertUniqueMembers } from '../lib/json-guard.mjs'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..')
const vectors = JSON.parse(
  readFileSync(path.join(repoRoot, 'conformance', 'v1', 'golden-vectors.json'), 'utf8'),
)

const clone = (value) => JSON.parse(JSON.stringify(value))
const sorted = (list) => [...list].sort()
const dimensionStatuses = (report) =>
  Object.fromEntries(
    Object.entries(report.dimensions).map(([name, dimension]) => [name, dimension.status ?? 'COMPOSITE']),
  )

for (const conformanceCase of vectors.cases) {
  test(`conformance: ${conformanceCase.id} (${conformanceCase.attack})`, async () => {
    let heldState = null
    for (const [index, step] of conformanceCase.steps.entries()) {
      const label = `${conformanceCase.id}#${index + 1}`
      const rawText =
        step.rawBundle !== undefined
          ? vectors.rawBundles[step.rawBundle]
          : JSON.stringify(vectors.bundles[step.bundle])

      if (step.expect.outcome === 'UNUSABLE_INPUT') {
        assert.throws(
          () => {
            assertUniqueMembers(rawText)
            JSON.parse(rawText)
          },
          (error) => error instanceof DuplicateMemberError || error instanceof SyntaxError,
          `${label}: must be refused as unusable input`,
        )
        continue
      }

      assertUniqueMembers(rawText)
      const report = await verifyBundle(JSON.parse(rawText), {
        pin: vectors.pin,
        expectedTenantId: step.options.tenant ?? null,
        tsaRoots:
          step.options.tsaRoots === true
            ? vectors.tsaRoots
            : step.options.tsaRoots === 'wrong'
              ? vectors.wrongTsaRoots
              : null,
        state: step.options.state === 'held' ? heldState : null,
      })
      heldState = clone(report.state)

      assert.equal(report.verdict, step.expect.verdict, `${label}: ${conformanceCase.description}`)
      assert.deepEqual(sorted(report.reasonCodes), sorted(step.expect.reasonCodes), `${label}: reason codes`)
      assert.deepEqual(dimensionStatuses(report), step.expect.dimensions, `${label}: dimensions`)
      assert.deepEqual(report.state, step.expect.state, `${label}: returned state`)
    }
  })
}

test('no corrupted fixture can return FULLY_VERIFIED', () => {
  // The acceptance criterion, asserted as a sweep rather than trusted case by
  // case: FULLY_VERIFIED appears only on the explicitly-valid cases.
  for (const conformanceCase of vectors.cases) {
    for (const step of conformanceCase.steps) {
      if (step.expect.outcome === 'REPORT' && step.expect.verdict === 'FULLY_VERIFIED') {
        assert.ok(
          conformanceCase.id.startsWith('valid-') ||
            conformanceCase.id === 'equivalent-serialization-accepted' ||
            conformanceCase.id === 'respelled-timestamp-equivalent',
          `${conformanceCase.id} reaches FULLY_VERIFIED but is not a declared-valid case`,
        )
      }
    }
  }
})

test('every attack-matrix row has at least one case', () => {
  const rows = Object.entries(vectors.attackMatrix)
  assert.ok(rows.length >= 15, 'the matrix index is populated')
  for (const [attack, caseIds] of rows) {
    assert.ok(caseIds.length > 0, `attack row ${attack} has no case`)
  }
})

test('a duplicate member name hides behind no escape spelling', () => {
  // Member equality is decided on DECODED names, exactly as JSON.parse reads
  // them — the raw spellings "a", "a" and "\/" vs "/" are one name each.
  const refused = [
    '{"a":1,"\u0061":2}', // a decodes to "a"
    '{"/":1,"\/":2}', // escaped solidus decodes to "/"
    '{"\ud83d\ude00":1,"😀":2}', // surrogate-pair escapes equal the literal
    '{"line\nbreak":1,"line\nbreak":2}', // control escape (raw LF is not valid JSON, but decoded equality still holds)
  ]
  for (const text of refused) {
    assert.throws(
      () => assertUniqueMembers(text),
      DuplicateMemberError,
      `must refuse: ${JSON.stringify(text)}`,
    )
  }
  // Genuinely distinct names stay accepted, escapes or not.
  assert.doesNotThrow(() => assertUniqueMembers('{"a":1,"\u0062":2,"nested":{"a":3}}'))
  assert.doesNotThrow(() => assertUniqueMembers('{"list":[{"a":1},{"a":2}],"a":3}'))
})
