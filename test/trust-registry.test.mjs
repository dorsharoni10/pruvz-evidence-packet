// Proves this runtime reproduces the published trust-registry vectors exactly,
// accepts every history the specification says must be accepted, and refuses
// every one it says must be refused — with the same reason code.
//
// These vectors are the agreement point between two independent
// implementations: this one and the .NET implementation inside pruvz-core,
// which vendors this same file and runs the same case tables. A rotation one
// runtime honours and the other does not is a broken trust registry, and the
// vectors are how that shows up as a failing test instead of as a customer
// whose evidence stopped verifying.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  KEY_STATES,
  KEY_STATUSES,
  KEY_USES,
  REFUSAL_CODES,
  SEAL_REASON_CODES,
  SUITES,
  TRUST_REGISTRY_FORMAT_VERSION,
  TrustRegistryError,
  acceptChain,
  jwkThumbprint,
  keyStateAt,
  manifestDigest,
  manifestInput,
  rootPinFromManifest,
  sealSigningInput,
  validateRegistryDocument,
  verifyManifest,
  verifySeal,
} from '../lib/trust-registry.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(path.join(here, '..', 'trust-registry', 'v1', 'golden-vectors.json'), 'utf8'),
)

const documentFor = (id) => {
  const document = vectors.documents[id] ?? vectors.badDocuments[id]
  assert.ok(document !== undefined, `the vectors declare no document "${id}"`)
  return document
}

const refusalCode = (fn) => {
  try {
    fn()
  } catch (error) {
    assert.ok(error instanceof TrustRegistryError, `expected a TrustRegistryError, got ${error}`)
    return error.code
  }
  return null
}

const sorted = (values) => [...values].sort()

/** The header separator, spelled out so no source file has to carry a raw NUL. */
const NUL = String.fromCharCode(0)

test('the vectors were published for the format this runtime speaks', () => {
  assert.equal(vectors.trustRegistryFormatVersion, TRUST_REGISTRY_FORMAT_VERSION)
  assert.equal(vectors.domainSeparation.registry.tag, 'pruvz.ai/trust-registry')
  assert.equal(vectors.domainSeparation.seal.tag, 'pruvz.ai/evidence-signature')
  // The two domains must stay distinct, or a manifest's signing input could be
  // presented as a seal's.
  assert.notEqual(vectors.domainSeparation.registry.tag, vectors.domainSeparation.seal.tag)
})

test('every published thumbprint is reproduced from the key alone', () => {
  for (const { id, jwk, thumbprint } of vectors.thumbprints) {
    assert.equal(jwkThumbprint(jwk), thumbprint, `thumbprint of ${id}`)
  }
})

test('a pin is derived from the first manifest and matches the published one', () => {
  assert.deepEqual(rootPinFromManifest(vectors.documents.v1), vectors.pin)
})

test('the canonical bytes of registry version 1 are reproduced exactly', () => {
  const input = manifestInput(vectors.documents.v1.manifest)
  const separator = input.indexOf(0, input.indexOf(0) + 1)

  assert.equal(input.subarray(separator + 1).toString('utf8'), vectors.canonical.manifestV1)
  assert.equal(input.length, vectors.canonical.manifestV1SigningInputByteLength)

  // The header is derived from the version inside the signed document, never
  // read from a second unsigned copy of it.
  assert.equal(
    input.subarray(0, separator + 1).toString('utf8'),
    `pruvz.ai/trust-registry${NUL}${TRUST_REGISTRY_FORMAT_VERSION}${NUL}`,
  )
})

test('every published manifest digest is reproduced exactly', () => {
  for (const [id, digest] of Object.entries(vectors.digests)) {
    assert.equal(manifestDigest(documentFor(id).manifest), digest, `digest of ${id}`)
  }
})

test('the seal signing input is reproduced from the envelope alone', () => {
  const input = sealSigningInput(vectors.seals.s1.envelope)
  assert.equal(input.toString('base64'), vectors.canonical.sealS1SigningInputBase64)
  assert.equal(input.length, vectors.canonical.sealS1SigningInputByteLength)
})

test('each published manifest links to its predecessor by that predecessor’s digest', () => {
  const order = ['v1', 'v2', 'v3', 'v4', 'v5']
  for (let index = 1; index < order.length; index += 1) {
    const { manifest } = validateRegistryDocument(vectors.documents[order[index]])
    assert.deepEqual(manifest.previous, {
      digest: vectors.digests[order[index - 1]],
      registryVersion: index,
    })
  }
})

test('chain cases behave exactly as published', () => {
  for (const scenario of vectors.chainCases) {
    const pin = 'pinOverride' in scenario ? scenario.pinOverride : vectors.pin

    let state = null
    for (const id of scenario.establish) {
      state = acceptChain([documentFor(id)], { pin, state }).state
    }

    const attempt = () =>
      acceptChain(
        scenario.attempt.map((id) => documentFor(id)),
        { pin, state },
      )

    if (scenario.expect === 'ACCEPT') {
      const accepted = attempt()
      assert.equal(
        accepted.state.registryVersion,
        scenario.expectedRegistryVersion,
        `${scenario.id}: registry version`,
      )
      assert.equal(accepted.state.digest, scenario.expectedDigest, `${scenario.id}: digest`)
      continue
    }

    assert.equal(refusalCode(attempt), scenario.expect, `${scenario.id}: ${scenario.description}`)
  }
})

test('a rolled-back manifest is refused even though it verifies on its own', () => {
  // The point worth stating separately: the stale document is not corrupt. It
  // was signed by the real root and passes every structural rule; only the
  // history a verifier already holds makes it a refusal.
  const stale = vectors.documents.v1
  assert.ok(verifyManifest(stale, { pin: vectors.pin }))

  const state = acceptChain(
    ['v1', 'v2', 'v3'].map((id) => documentFor(id)),
    { pin: vectors.pin },
  ).state
  assert.equal(
    refusalCode(() => acceptChain([stale], { pin: vectors.pin, state })),
    'REGISTRY_ROLLBACK',
  )
})

test('verifier state may only be continued under the anchor that produced it', () => {
  // Two roots are two histories, and their version numbers say nothing about
  // each other. Without this rule a verifier handed state from another trust
  // domain would compare versions across unrelated histories and answer
  // REGISTRY_ROLLBACK — a refusal that names the wrong mistake — or, when the
  // foreign history happened to sit lower, accept.
  const state = acceptChain(
    ['v1', 'v2', 'v3'].map((id) => documentFor(id)),
    { pin: vectors.pin },
  ).state

  assert.equal(state.issuer, vectors.pin.issuer)
  assert.equal(state.root, vectors.pin.root)

  assert.equal(
    refusalCode(() =>
      acceptChain([documentFor('v4')], {
        pin: { ...vectors.pin, issuer: 'not-pruvz.example' },
        state,
      }),
    ),
    'ISSUER_MISMATCH',
  )

  assert.equal(
    refusalCode(() =>
      acceptChain([documentFor('v4')], {
        pin: { ...vectors.pin, root: `sha256:${'A'.repeat(43)}` },
        state,
      }),
    ),
    'ROOT_MISMATCH',
  )

  // A state that does not record its anchor at all cannot be continued either:
  // it is indistinguishable from one that belongs somewhere else.
  const { issuer, root, ...anchorless } = state
  assert.equal(
    refusalCode(() => acceptChain([documentFor('v4')], { pin: vectors.pin, state: anchorless })),
    'NO_TRUST_ANCHOR',
  )

  // And the anchor check happens BEFORE any version comparison, so a missing
  // pin is still the refusal it always was rather than a crash.
  assert.equal(
    refusalCode(() => acceptChain([documentFor('v4')], { pin: null, state })),
    'NO_TRUST_ANCHOR',
  )
})

test('structural refusal cases behave exactly as published', () => {
  for (const scenario of vectors.refusalCases) {
    assert.equal(
      refusalCode(() => verifyManifest(documentFor(scenario.document), { pin: vectors.pin })),
      scenario.expect,
      `${scenario.id}: ${scenario.description}`,
    )
  }
})

test('seal cases produce exactly the published verdicts', () => {
  for (const scenario of vectors.sealCases) {
    const { manifest } = verifyManifest(vectors.documents[scenario.registry], { pin: vectors.pin })

    const result = verifySeal({
      seal: vectors.seals[scenario.seal],
      manifest,
      expectedSubject: vectors.subjects[scenario.subject],
      expectedCommitmentDigest:
        scenario.commitmentDigest === null
          ? null
          : vectors.expectedCommitmentDigests[scenario.commitmentDigest],
    })

    assert.equal(result.verdict, scenario.expectedVerdict, `${scenario.id}: ${scenario.description}`)
    assert.deepEqual(
      sorted(result.reasonCodes),
      sorted(scenario.expectedReasonCodes),
      `${scenario.id}: reason codes`,
    )
    if (scenario.expectedDimensions !== undefined) {
      assert.deepEqual(result.dimensions, scenario.expectedDimensions, `${scenario.id}: dimensions`)
    }
    // Nothing that failed or was left unchecked may ever be reported as the
    // strongest verdict. This is the rule PRUVZ-88 maps onto FULLY_VERIFIED, so
    // it is asserted here rather than trusted downstream.
    if (result.verdict === 'VALID') {
      assert.equal(result.dimensions.content, 'MATCHES', `${scenario.id}: VALID requires content`)
      assert.equal(result.dimensions.signature, 'VALID')
      assert.equal(result.dimensions.subject, 'MATCHES')
      assert.equal(result.dimensions.keyIdentity, 'TRUSTED')
    }
  }
})

test('a revoked root weakens every seal under it, however good the signature', () => {
  const { manifest } = verifyManifest(vectors.documents.v1, { pin: vectors.pin })
  const result = verifySeal({
    seal: vectors.seals.s1,
    manifest,
    expectedSubject: vectors.subjects.s1,
    expectedCommitmentDigest: vectors.expectedCommitmentDigests.s1,
    registryReasonCodes: ['ROOT_REVOKED'],
  })

  assert.equal(result.verdict, 'PARTIAL')
  assert.ok(result.reasonCodes.includes('ROOT_REVOKED'))
  // The signature itself is untouched — that is precisely why the root's own
  // status has to travel with the verdict.
  assert.equal(result.dimensions.signature, 'VALID')
})

test('key lifecycle is answered per instant, not read off the declared status', () => {
  const { manifest } = verifyManifest(vectors.documents.v5, { pin: vectors.pin })
  const k1 = manifest.keys.find((key) => key.retiredAtUtc !== null)

  assert.equal(k1.status, 'REVOKED', 'the manifest declares where the key stood when it was issued')
  assert.equal(keyStateAt(k1, vectors.timeline.s1), 'ACTIVE', 'but it was active when it signed')
  assert.equal(keyStateAt(k1, vectors.timeline.v3), 'RETIRED')
  assert.equal(keyStateAt(k1, vectors.timeline.v4), 'REVOKED')
  assert.equal(keyStateAt(k1, '2026-07-31T23:59:59Z'), 'NOT_YET_VALID')

  // Revocation wins where the windows overlap: the key is retired from v3 and
  // revoked from a later instant, and the stronger statement is the true one.
  assert.equal(keyStateAt(k1, vectors.timeline.k1Revoked), 'REVOKED')
})

test('a fractional second never sorts a lifecycle boundary the wrong way', () => {
  // The trap this guards: canonical timestamps omit a zero fraction, so a naive
  // lexical compare puts "…:00Z" AFTER "…:00.5Z" because 'Z' > '.'.
  const key = {
    retiredAtUtc: null,
    revokedAtUtc: '2026-08-01T00:00:00Z',
    validFromUtc: '2026-07-01T00:00:00Z',
  }
  assert.equal(keyStateAt(key, '2026-07-31T23:59:59.999Z'), 'ACTIVE')
  assert.equal(keyStateAt(key, '2026-08-01T00:00:00Z'), 'REVOKED')
  assert.equal(keyStateAt(key, '2026-08-01T00:00:00.001Z'), 'REVOKED')
})

test('no published key entry carries private material', () => {
  for (const document of Object.values(vectors.documents)) {
    for (const key of document.manifest.keys) {
      assert.deepEqual(sorted(Object.keys(key.publicKey)), ['crv', 'kty', 'x', 'y'])
    }
  }
})

test('the refusal and reason vocabularies are closed and sorted', () => {
  assert.deepEqual(REFUSAL_CODES, sorted(REFUSAL_CODES))
  assert.deepEqual(new Set(REFUSAL_CODES).size, REFUSAL_CODES.length)
  assert.deepEqual(new Set(SEAL_REASON_CODES).size, SEAL_REASON_CODES.length)

  for (const scenario of [...vectors.chainCases, ...vectors.refusalCases]) {
    if (scenario.expect !== 'ACCEPT') {
      assert.ok(REFUSAL_CODES.includes(scenario.expect), `${scenario.expect} is a known refusal`)
    }
  }
  for (const scenario of vectors.sealCases) {
    for (const code of scenario.expectedReasonCodes) {
      assert.ok(SEAL_REASON_CODES.includes(code), `${code} is a known seal reason`)
    }
  }

  assert.deepEqual(KEY_USES, ['trust-root', 'evidence-signing'])
  assert.deepEqual(KEY_STATUSES, ['ACTIVE', 'RETIRED', 'REVOKED'])
  assert.deepEqual(KEY_STATES, ['NOT_YET_VALID', 'ACTIVE', 'RETIRED', 'REVOKED'])
  // A suite is here only because a provider Pruvz integrates with signs with
  // it. Widening this list is a provider integration, not an edit.
  assert.deepEqual(Object.keys(SUITES), ['ES256', 'ES384'])
})
