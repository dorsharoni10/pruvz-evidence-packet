// PRUVZ-101: one version stream across npm, PyPI and NuGet, enforced
// mechanically on every test run — not left to release-day discipline.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { checkVersions } from '../bin/check-versions.mjs'

test('the npm, PyPI and NuGet versions are one stream', () => {
  const { problems } = checkVersions()
  assert.deepEqual(problems, [])
})

test('a tag that disagrees with the stream is refused', () => {
  const { problems } = checkVersions('v0.0.0-not-the-version')
  assert.equal(problems.length, 1)
})
