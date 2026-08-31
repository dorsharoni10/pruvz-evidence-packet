#!/usr/bin/env node
// Usage: node bin/check-versions.mjs [vX.Y.Z]
//
// PRUVZ-101 invariant: one version stream. The npm package, the Python
// package and the .NET packages must carry the same version — and on release,
// that version must be the dispatched tag. This check is mechanical, not a
// convention: npm test runs it on every change (via test/versions.test.mjs)
// and the release workflow runs it against the tag before anything is built.
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

const extract = (file, pattern, what) => {
  const match = readFileSync(join(repoRoot, file), 'utf8').match(pattern)
  if (match === null) throw new Error(`${what}: no version found in ${file}`)
  return match[1]
}

export const readVersions = () => ({
  'package.json (npm)': JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')).version,
  'conformance/python/pyproject.toml (PyPI)': extract(
    'conformance/python/pyproject.toml',
    // \r? — a Windows checkout with autocrlf may hand this file over as CRLF.
    /^version = "([^"]+)"\r?$/mu,
    'PyPI version',
  ),
  'dotnet/Directory.Build.props (NuGet)': extract(
    'dotnet/Directory.Build.props',
    /<Version>([^<]+)<\/Version>/u,
    'NuGet version',
  ),
})

export const checkVersions = (expectedTag = null) => {
  const versions = readVersions()
  const values = [...new Set(Object.values(versions))]
  const problems = []
  if (values.length !== 1) {
    problems.push(
      `the version stream diverged: ${Object.entries(versions)
        .map(([file, version]) => `${file} = ${version}`)
        .join(', ')}`,
    )
  }
  if (expectedTag !== null && `v${values[0]}` !== expectedTag) {
    problems.push(`the release tag ${expectedTag} does not match the package version v${values[0]}`)
  }
  return { versions, problems }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { versions, problems } = checkVersions(process.argv[2] ?? null)
  for (const [file, version] of Object.entries(versions)) console.log(`${version}  ${file}`)
  for (const problem of problems) console.error(`FAIL  ${problem}`)
  process.exit(problems.length > 0 ? 1 : 0)
}
