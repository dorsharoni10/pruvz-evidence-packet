// Reference implementation of the Pruvz Public Trust Registry, format version 1.
//
// A signature (product PRUVZ-94) answers "who committed to this record?" only as
// well as the answer to "and how do you know that key is theirs?". Until now the
// public half of a signing key was resolved through the Pruvz deployment's own
// signer, so a compromised deployment could answer with a key of its choosing.
// That is not independent verification, and this repository has never described
// it as one.
//
// The trust registry closes that gap the only way it can be closed honestly. No
// verifier can identify "the Pruvz signer" with literally zero bootstrap trust,
// so the goal is not "trust nothing about Pruvz". It is:
//
//   1. bootstrap trust ONCE, out of band, by pinning a root fingerprint;
//   2. make every later key rotation and revocation independently auditable
//      against that pin;
//   3. never let mutable Pruvz application state decide key history.
//
// Everything here fails closed. No pin means no verification — a verifier that
// accepted whatever key list it was handed would be the very thing this file
// exists to prevent. And there is no boolean result: a seal is reported across
// dimensions, because "the signature is valid" and "the key was trustworthy
// when it signed" are different questions with different answers.
//
// This file is the second-runtime reference for the .NET implementation in
// pruvz-core. Neither is authoritative on its own: both must reproduce the
// published golden vectors in trust-registry/v1/golden-vectors.json.
import { createHash, createPublicKey, verify as verifyEcdsa } from 'node:crypto'

import { canonicalTimestamp, canonicalize } from './canonical.mjs'

/** The trust-registry manifest format this implementation speaks. */
export const TRUST_REGISTRY_FORMAT_VERSION = '1'

/** The evidence-envelope format this implementation can verify (product PRUVZ-94). */
export const SEAL_ENVELOPE_VERSION = '1'

/**
 * Domain-separation tags. Distinct from the commitment layer's
 * "pruvz.ai/commitment", so no byte string signed in one domain can ever be
 * re-read as a document of another.
 */
const REGISTRY_DOMAIN_TAG = 'pruvz.ai/trust-registry'
const SEAL_DOMAIN_TAG = 'pruvz.ai/evidence-signature'

/** The header field separator: a NUL byte, as everywhere else in this contract. */
const HEADER_SEPARATOR = '\u0000'

/**
 * What a key is for. The distinction is load-bearing rather than descriptive: a
 * root key signs the key history itself, an evidence key signs records, and a
 * verifier must never accept one in the other's place. A root that could also
 * seal evidence would let whoever controls key history mint records; an evidence
 * key that could sign the manifest would let an application compromise rewrite
 * which keys are trusted.
 */
export const KEY_USES = ['trust-root', 'evidence-signing']

/** The lifecycle status a manifest declares for a key, as of its own issue time. */
export const KEY_STATUSES = ['ACTIVE', 'RETIRED', 'REVOKED']

/**
 * The lifecycle state of a key AT a given instant, which is a different
 * question from the status a manifest declares: a manifest states where a key
 * stood when the manifest was issued, and a seal asks where the key stood when
 * it signed. NOT_YET_VALID exists only as an answer to the second question.
 */
export const KEY_STATES = ['NOT_YET_VALID', 'ACTIVE', 'RETIRED', 'REVOKED']

/**
 * The signature suites a registry may name. Closed, and identical to the
 * product's closed registry (pruvz-core, SigningSuite): a suite appears here
 * only because a provider Pruvz actually integrates with signs with it.
 *
 * `coordinateLength` is not cosmetic. RFC 7518 requires the EC coordinates of a
 * JWK to be the curve's fixed field width, zero-padded — and a thumbprint is
 * computed over those exact octets, so a key whose coordinates were trimmed of
 * a leading zero byte would thumbprint differently on two runtimes and break a
 * pin for no reason anybody could see.
 */
export const SUITES = {
  ES256: { crv: 'P-256', hash: 'sha256', coordinateLength: 32, signatureLength: 64 },
  ES384: { crv: 'P-384', hash: 'sha384', coordinateLength: 48, signatureLength: 96 },
}

/** The complete member set of a public JWK in this contract. */
const JWK_MEMBERS = ['crv', 'kty', 'x', 'y']

/** The complete member set of one published key entry. */
const KEY_MEMBERS = [
  'keyId',
  'predecessorKeyId',
  'provider',
  'publicKey',
  'retiredAtUtc',
  'revocationReason',
  'revokedAtUtc',
  'status',
  'suite',
  'thumbprint',
  'use',
  'validFromUtc',
]

/** The complete member set of the signed manifest. */
const MANIFEST_MEMBERS = [
  'formatVersion',
  'issuedAtUtc',
  'issuer',
  'keys',
  'previous',
  'registryVersion',
]

/** The longest a single string in a manifest may be. */
const MAX_TEXT_LENGTH = 512

/**
 * Every reason the trust layer refuses a document outright. The codes are part
 * of the specification: a golden vector names the code it expects, so two
 * runtimes must refuse the same input for the same reason — not merely both
 * throw.
 */
export const REFUSAL_CODES = [
  'AMBIGUOUS_ROOT',
  'DUPLICATE_KEY_ID',
  'INVALID_MANIFEST',
  'INVALID_PUBLIC_KEY',
  'INVALID_SIGNATURE_ENCODING',
  'ISSUER_MISMATCH',
  'KEY_NOT_YET_VALID',
  'KEY_STATUS_INCONSISTENT',
  'MALFORMED_SIGNATURE',
  'NO_TRUST_ANCHOR',
  'PRIVATE_KEY_MATERIAL',
  'REGISTRY_CHAIN_BROKEN',
  'REGISTRY_FORK',
  'REGISTRY_ROLLBACK',
  'REGISTRY_SIGNATURE_INVALID',
  'ROOT_MISMATCH',
  'TEXT_OUT_OF_BOUNDS',
  'THUMBPRINT_MISMATCH',
  'UNKNOWN_KEY_USE',
  'UNKNOWN_REGISTRY_FORMAT_VERSION',
  'UNKNOWN_SIGNER',
  'UNKNOWN_SUITE',
]

/**
 * The machine-readable reasons a seal verdict carries. These are NOT refusals:
 * a seal is answered, never thrown about, because "this seal is invalid" is a
 * result a caller must be able to render, not an exception it must catch.
 */
export const SEAL_REASON_CODES = [
  // Fatal — the verdict is INVALID.
  'COMMITMENT_MISMATCH',
  'KEY_PROVIDER_MISMATCH',
  'KEY_SUITE_MISMATCH',
  'KEY_USE_MISMATCH',
  'MALFORMED_ENVELOPE',
  'MALFORMED_SIGNATURE',
  'SIGNATURE_INVALID',
  'SIGNED_AFTER_RETIREMENT',
  'SIGNED_AFTER_REVOCATION',
  'SIGNED_BEFORE_KEY_VALID',
  'SUBJECT_MISMATCH',
  'UNKNOWN_ENVELOPE_VERSION',
  'UNKNOWN_KEY',
  // Weakening — the verdict is PARTIAL.
  'COMMITMENT_NOT_CHECKED',
  'COMMITTED_AT_SELF_ASSERTED',
  'ROOT_REVOKED',
  'SIGNED_BEFORE_REVOCATION',
  // Informational — the verdict stands.
  'KEY_RETIRED_AFTER_SIGNING',
  'ROOT_RETIRED',
]

/** Thrown for every refusal. There is no lenient mode. */
export class TrustRegistryError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'TrustRegistryError'
    this.code = code
  }
}

const fail = (code, message) => {
  throw new TrustRegistryError(code, message)
}

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

/**
 * A string that may appear in a manifest: present, non-empty and bounded. The
 * bound is what keeps a manifest a piece of machine metadata rather than a
 * place to put a document.
 */
const text = (value, field) => {
  if (typeof value !== 'string' || value.length === 0) {
    fail('INVALID_MANIFEST', `${field} is required and must be a non-empty string`)
  }
  if (value.length > MAX_TEXT_LENGTH) {
    fail('TEXT_OUT_OF_BOUNDS', `${field} must not exceed ${MAX_TEXT_LENGTH} characters`)
  }
  return value
}

const optionalText = (value, field) => (value === null ? null : text(value, field))

/**
 * A key id, which carries one restriction the other strings do not: printable
 * ASCII. That is not a style rule — this exact string is bound into signed
 * evidence envelopes under that restriction (product PRUVZ-94), so a registry
 * admitting a key id an envelope could never carry would name keys no seal can
 * ever refer to.
 */
const keyIdText = (value, field) => {
  const id = text(value, field)
  for (let index = 0; index < id.length; index += 1) {
    const code = id.charCodeAt(index)
    if (code < 0x20 || code > 0x7e) {
      fail(
        'INVALID_MANIFEST',
        `${field} must be printable ASCII: a key id is bound into signed evidence envelopes, ` +
          'which admit nothing else',
      )
    }
  }
  return id
}

/**
 * Decodes unpadded base64url strictly. A permissive decoder would accept two
 * spellings of one signature, and two spellings of one fact is exactly what
 * every canonical layer in this contract exists to prevent.
 */
const decodeBase64Url = (value, field, code = 'INVALID_SIGNATURE_ENCODING') => {
  if (typeof value !== 'string' || value.length === 0) {
    fail(code, `${field} is required and must be unpadded base64url`)
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    fail(code, `${field} is not unpadded base64url`)
  }
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.toString('base64url') !== value) {
    fail(code, `${field} is not a canonical unpadded base64url encoding`)
  }
  return bytes
}

/**
 * Widens a canonical UTC timestamp into a fixed-width form that compares
 * exactly as ordinary text.
 *
 * Canonical timestamps carry a fraction only when it is non-zero, so the
 * obvious lexical comparison is wrong in a way that would be very hard to see:
 * "…:00Z" sorts AFTER "…:00.5Z", because 'Z' is greater than '.'. Padding the
 * fraction to a fixed width makes every field fixed-width and zero-padded, so
 * ordinary string ordering is exact — with no Date, no millisecond truncation
 * and no floating point anywhere near a security boundary.
 *
 * Deliberately lexical, exactly like canonicalTimestamp: this fixes the
 * grammar, not the calendar. Whether an instant exists is the schema's
 * business.
 */
const comparableInstant = (value, field) => {
  let canonical
  try {
    canonical = canonicalTimestamp(value)
  } catch (error) {
    return fail('INVALID_MANIFEST', `${field}: ${error.message}`)
  }
  const [, seconds, fraction = ''] = /^(.+?)(?:\.(\d+))?Z$/.exec(canonical)
  return `${seconds}.${fraction.padEnd(9, '0')}`
}

/**
 * Validates a public JWK and refuses anything that is not exactly one.
 *
 * The member set is closed for a concrete reason: a thumbprint covers only the
 * four required members, so an extra member would ride along un-thumbprinted
 * and a pin would not notice it. And a JWK carrying `d` is refused outright —
 * Node will happily build a working public key from a private JWK, so
 * everything would appear fine while a private key sat in a document this
 * contract promises never contains one.
 */
function requirePublicJwk(jwk, field) {
  if (!isPlainObject(jwk)) {
    fail('INVALID_PUBLIC_KEY', `${field} must be a JSON Web Key object`)
  }
  if ('d' in jwk) {
    fail(
      'PRIVATE_KEY_MATERIAL',
      `${field} carries a private component (d). A trust registry publishes public halves only, ` +
        'and a private JWK would otherwise build a working public key and pass unnoticed',
    )
  }

  const unknown = Object.keys(jwk).filter((member) => !JWK_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail(
      'INVALID_PUBLIC_KEY',
      `${field} carries ${unknown.join(', ')}; a public JWK here holds exactly ` +
        `${JWK_MEMBERS.join(', ')}, because the thumbprint covers those and nothing else`,
    )
  }
  const missing = JWK_MEMBERS.filter((member) => !(member in jwk))
  if (missing.length > 0) {
    fail('INVALID_PUBLIC_KEY', `${field} is missing ${missing.join(', ')}`)
  }

  if (jwk.kty !== 'EC') {
    fail('INVALID_PUBLIC_KEY', `${field}.kty must be "EC"`)
  }

  const suite = Object.values(SUITES).find((candidate) => candidate.crv === jwk.crv)
  if (suite === undefined) {
    fail(
      'INVALID_PUBLIC_KEY',
      `${field}.crv "${jwk.crv}" is not a curve this registry format defines`,
    )
  }

  for (const coordinate of ['x', 'y']) {
    const bytes = decodeBase64Url(jwk[coordinate], `${field}.${coordinate}`, 'INVALID_PUBLIC_KEY')
    if (bytes.length !== suite.coordinateLength) {
      fail(
        'INVALID_PUBLIC_KEY',
        `${field}.${coordinate} is ${bytes.length} bytes; curve ${jwk.crv} requires exactly ` +
          `${suite.coordinateLength}, zero-padded (RFC 7518) — a trimmed coordinate would ` +
          'thumbprint differently and silently break a pin',
      )
    }
  }

  return jwk
}

/**
 * The RFC 7638 thumbprint of a public JWK, as "sha256:" followed by the
 * unpadded base64url digest.
 *
 * The suite is named rather than assumed, for the same reason a commitment
 * names its digest suite: a future one must be a decision, never a default. The
 * part after the colon is exactly the RFC 7638 thumbprint, so a pin taken with
 * any standard tool still matches.
 */
export function jwkThumbprint(jwk) {
  const key = requirePublicJwk(jwk, 'publicKey')
  // RFC 7638: the required members, lexicographically ordered, no whitespace —
  // which is precisely what this contract's canonical serializer produces.
  const canonical = canonicalize({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })
  return `sha256:${createHash('sha256').update(canonical).digest('base64url')}`
}

/**
 * Refuses a manifest format version this implementation cannot speak, before
 * any byte of it is trusted — the same rule the commitment and envelope layers
 * apply to their own versions.
 */
export function requireSupported(formatVersion) {
  if (formatVersion !== TRUST_REGISTRY_FORMAT_VERSION) {
    fail(
      'UNKNOWN_REGISTRY_FORMAT_VERSION',
      `Unknown trust-registry format version ${
        formatVersion === undefined ? '(none)' : `"${formatVersion}"`
      }. This implementation speaks version ${TRUST_REGISTRY_FORMAT_VERSION}.`,
    )
  }
}

/**
 * The exact byte string a manifest signature covers:
 *
 *   "pruvz.ai/trust-registry" 0x00 formatVersion 0x00 <canonical JSON of manifest>
 *
 * Only the `manifest` member is signed. `signatures` obviously cannot be, and
 * `attestations` deliberately is not — see acceptChain.
 */
export function manifestInput(manifest) {
  if (!isPlainObject(manifest)) {
    fail('INVALID_MANIFEST', 'manifest must be an object')
  }
  requireSupported(manifest.formatVersion)
  const header = [REGISTRY_DOMAIN_TAG, TRUST_REGISTRY_FORMAT_VERSION, ''].join(HEADER_SEPARATOR)
  return Buffer.concat([Buffer.from(header, 'utf8'), canonicalize(manifest)])
}

/**
 * The digest of a manifest: "sha256:" and 64 lowercase hex digits, over exactly
 * the bytes the signature covers. One byte string, one digest, one signature —
 * so a `previous` link and a signature can never disagree about which manifest
 * they mean.
 */
export function manifestDigest(manifest) {
  return `sha256:${createHash('sha256').update(manifestInput(manifest)).digest('hex')}`
}

/**
 * Where a key stood at one instant. This is the whole of the time-aware
 * lifecycle, and every consumer asks it rather than reading `status`, which
 * only ever describes the manifest's own issue time.
 *
 * Revocation wins over retirement when both apply. A key is normally retired
 * first and revoked later only if something went wrong, but a revocation is
 * routinely back-dated to when a compromise is believed to have started — so
 * the two windows can overlap, and the stronger statement is the true one.
 */
export function keyStateAt(key, instant) {
  const when = comparableInstant(instant, 'instant')

  if (key.revokedAtUtc !== null && when >= comparableInstant(key.revokedAtUtc, 'revokedAtUtc')) {
    return 'REVOKED'
  }
  if (key.retiredAtUtc !== null && when >= comparableInstant(key.retiredAtUtc, 'retiredAtUtc')) {
    return 'RETIRED'
  }
  if (when < comparableInstant(key.validFromUtc, 'validFromUtc')) {
    return 'NOT_YET_VALID'
  }
  return 'ACTIVE'
}

const requireExactMembers = (value, expected, field, code = 'INVALID_MANIFEST') => {
  const declared = Object.keys(value)
  const unknown = declared.filter((member) => !expected.includes(member))
  const missing = expected.filter((member) => !declared.includes(member))
  if (unknown.length > 0 || missing.length > 0) {
    fail(
      code,
      `${field} must declare exactly ${expected.join(', ')}` +
        `${unknown.length > 0 ? `; unexpected: ${unknown.join(', ')}` : ''}` +
        `${missing.length > 0 ? `; missing: ${missing.join(', ')}` : ''}`,
    )
  }
}

const validateKey = (raw, field, issuedAtUtc) => {
  if (!isPlainObject(raw)) {
    fail('INVALID_MANIFEST', `${field} must be an object`)
  }
  requireExactMembers(raw, KEY_MEMBERS, field)

  const key = {
    keyId: keyIdText(raw.keyId, `${field}.keyId`),
    predecessorKeyId:
      raw.predecessorKeyId === null
        ? null
        : keyIdText(raw.predecessorKeyId, `${field}.predecessorKeyId`),
    provider: text(raw.provider, `${field}.provider`),
    publicKey: requirePublicJwk(raw.publicKey, `${field}.publicKey`),
    retiredAtUtc: optionalText(raw.retiredAtUtc, `${field}.retiredAtUtc`),
    revocationReason: optionalText(raw.revocationReason, `${field}.revocationReason`),
    revokedAtUtc: optionalText(raw.revokedAtUtc, `${field}.revokedAtUtc`),
    status: raw.status,
    suite: raw.suite,
    thumbprint: text(raw.thumbprint, `${field}.thumbprint`),
    use: raw.use,
    validFromUtc: text(raw.validFromUtc, `${field}.validFromUtc`),
  }

  if (!KEY_USES.includes(key.use)) {
    fail('UNKNOWN_KEY_USE', `${field}.use must be one of ${KEY_USES.join(', ')}`)
  }
  if (!Object.hasOwn(SUITES, key.suite)) {
    fail('UNKNOWN_SUITE', `${field}.suite must be one of ${Object.keys(SUITES).join(', ')}`)
  }
  if (SUITES[key.suite].crv !== key.publicKey.crv) {
    fail(
      'INVALID_PUBLIC_KEY',
      `${field}: suite ${key.suite} signs on ${SUITES[key.suite].crv}, but the key is on ` +
        `${key.publicKey.crv}`,
    )
  }
  if (!KEY_STATUSES.includes(key.status)) {
    fail('INVALID_MANIFEST', `${field}.status must be one of ${KEY_STATUSES.join(', ')}`)
  }

  // The thumbprint is recomputed, never believed. It is present because a pin
  // is taken over it and an operator has to be able to read it out of the
  // document — a derivation that is checked, not a second source of truth.
  const computed = jwkThumbprint(key.publicKey)
  if (computed !== key.thumbprint) {
    fail(
      'THUMBPRINT_MISMATCH',
      `${field}.thumbprint is ${key.thumbprint} but the public key thumbprints to ${computed}`,
    )
  }

  if (key.revocationReason !== null && key.revokedAtUtc === null) {
    fail('INVALID_MANIFEST', `${field}.revocationReason is set on a key that is not revoked`)
  }

  // A registry records the keys it has, never keys it intends to have. A key
  // dated into the future would have no declarable status at all, and would let
  // a manifest promise a signer nobody could yet have used.
  if (
    comparableInstant(key.validFromUtc, `${field}.validFromUtc`) >
    comparableInstant(issuedAtUtc, 'manifest.issuedAtUtc')
  ) {
    fail(
      'KEY_NOT_YET_VALID',
      `${field}.validFromUtc is after the manifest's own issuedAtUtc`,
    )
  }

  // The declared status must be the state the timestamps put the key in at the
  // moment the manifest was issued. Without this a manifest could label a key
  // ACTIVE while carrying a revocation date in the past, and a reader who
  // trusted the label would trust a revoked key.
  const stateAtIssue = keyStateAt(key, issuedAtUtc)
  if (stateAtIssue !== key.status) {
    fail(
      'KEY_STATUS_INCONSISTENT',
      `${field}.status is ${key.status}, but its own timestamps put it at ${stateAtIssue} when ` +
        'the manifest was issued',
    )
  }

  return key
}

/**
 * Validates a published trust-registry document structurally, and returns it in
 * a normalized form. This establishes what the document *is*; it establishes
 * nothing about whether it should be believed — that is verifyManifest.
 */
export function validateRegistryDocument(document) {
  if (!isPlainObject(document)) {
    fail('INVALID_MANIFEST', 'A trust-registry document must be an object')
  }
  requireExactMembers(document, ['attestations', 'manifest', 'signatures'], 'The document')

  const raw = document.manifest
  if (!isPlainObject(raw)) {
    fail('INVALID_MANIFEST', 'document.manifest must be an object')
  }
  requireExactMembers(raw, MANIFEST_MEMBERS, 'manifest')
  requireSupported(raw.formatVersion)

  if (!Number.isInteger(raw.registryVersion) || raw.registryVersion < 1) {
    fail('INVALID_MANIFEST', 'manifest.registryVersion must be an integer of at least 1')
  }

  const issuedAtUtc = text(raw.issuedAtUtc, 'manifest.issuedAtUtc')
  comparableInstant(issuedAtUtc, 'manifest.issuedAtUtc')

  if ((raw.registryVersion === 1) !== (raw.previous === null)) {
    fail(
      'REGISTRY_CHAIN_BROKEN',
      raw.registryVersion === 1
        ? 'The first manifest has no predecessor, so manifest.previous must be null'
        : 'Only the first manifest may have a null manifest.previous',
    )
  }

  let previous = null
  if (raw.previous !== null) {
    if (!isPlainObject(raw.previous)) {
      fail('INVALID_MANIFEST', 'manifest.previous must be an object or null')
    }
    requireExactMembers(raw.previous, ['digest', 'registryVersion'], 'manifest.previous')
    previous = {
      digest: text(raw.previous.digest, 'manifest.previous.digest'),
      registryVersion: raw.previous.registryVersion,
    }
    if (
      !Number.isInteger(previous.registryVersion) ||
      previous.registryVersion !== raw.registryVersion - 1
    ) {
      fail(
        'REGISTRY_CHAIN_BROKEN',
        `manifest.previous.registryVersion must be ${raw.registryVersion - 1}: the chain links ` +
          'each manifest to the one immediately before it, so no version can be skipped',
      )
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(previous.digest)) {
      fail('INVALID_MANIFEST', 'manifest.previous.digest must be "sha256:" and 64 lowercase hex')
    }
  }

  if (!Array.isArray(raw.keys) || raw.keys.length === 0) {
    fail('INVALID_MANIFEST', 'manifest.keys must be a non-empty array')
  }

  const manifest = {
    formatVersion: raw.formatVersion,
    issuedAtUtc,
    issuer: text(raw.issuer, 'manifest.issuer'),
    keys: raw.keys.map((key, index) => validateKey(key, `manifest.keys[${index}]`, issuedAtUtc)),
    previous,
    registryVersion: raw.registryVersion,
  }

  const ids = new Set()
  for (const key of manifest.keys) {
    if (ids.has(key.keyId)) {
      fail(
        'DUPLICATE_KEY_ID',
        `manifest.keys declares "${key.keyId}" more than once: one key id has one history`,
      )
    }
    ids.add(key.keyId)
  }
  for (const key of manifest.keys) {
    if (key.predecessorKeyId !== null && !ids.has(key.predecessorKeyId)) {
      fail(
        'INVALID_MANIFEST',
        `manifest.keys: "${key.keyId}" names predecessor "${key.predecessorKeyId}", which the ` +
          'manifest does not declare — rotation lineage must stay inside the published history',
      )
    }
  }

  if (!Array.isArray(document.signatures) || document.signatures.length === 0) {
    fail('INVALID_MANIFEST', 'document.signatures must be a non-empty array')
  }

  const signatures = document.signatures.map((entry, index) => {
    const field = `signatures[${index}]`
    if (!isPlainObject(entry)) {
      fail('INVALID_MANIFEST', `${field} must be an object`)
    }
    requireExactMembers(entry, ['keyId', 'signature', 'suite'], field)

    const keyId = keyIdText(entry.keyId, `${field}.keyId`)
    const signer = manifest.keys.find((key) => key.keyId === keyId)
    if (signer === undefined) {
      fail(
        'UNKNOWN_SIGNER',
        `${field} names key "${keyId}", which the manifest it signs does not declare. A manifest ` +
          'always publishes the identity that signed it',
      )
    }
    if (signer.use !== 'trust-root') {
      fail(
        'UNKNOWN_SIGNER',
        `${field} is made by "${keyId}", whose use is ${signer.use}. Only a trust-root key signs ` +
          'the key history; an evidence key that could would let a record signer rewrite trust',
      )
    }
    if (entry.suite !== signer.suite) {
      fail(
        'INVALID_MANIFEST',
        `${field}.suite is ${entry.suite} but key "${keyId}" is declared as ${signer.suite}`,
      )
    }
    const signature = decodeBase64Url(entry.signature, `${field}.signature`)
    if (signature.length !== SUITES[signer.suite].signatureLength) {
      fail(
        'MALFORMED_SIGNATURE',
        `${field}.signature is ${signature.length} bytes; a ${signer.suite} signature is exactly ` +
          `${SUITES[signer.suite].signatureLength} (r || s)`,
      )
    }
    return { keyId, signature, signer, suite: entry.suite }
  })

  const signerIds = new Set()
  for (const entry of signatures) {
    if (signerIds.has(entry.keyId)) {
      fail('INVALID_MANIFEST', `document.signatures names "${entry.keyId}" more than once`)
    }
    signerIds.add(entry.keyId)
  }

  if (document.attestations !== null && !isPlainObject(document.attestations)) {
    fail('INVALID_MANIFEST', 'document.attestations must be an object or null')
  }

  return { attestations: document.attestations, manifest, signatures }
}

/**
 * Verifies one ECDSA signature over the given bytes with a public JWK.
 * Returns a boolean rather than throwing: at every call site below a failed
 * signature is a verdict, not an exception.
 */
const signatureVerifies = (bytes, jwk, suite, signature) => {
  try {
    return verifyEcdsa(
      SUITES[suite].hash,
      bytes,
      { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      signature,
    )
  } catch {
    // A key the runtime cannot build, or a signature it cannot parse, is a
    // failed verification and nothing more interesting.
    return false
  }
}

/**
 * The pin an operator takes at onboarding: the issuer and the thumbprint of its
 * trust root, obtained OUT OF BAND — from a published repository release, a
 * signed onboarding document, or a channel the customer chose. Never from the
 * live API, which is precisely the thing a pin exists to check.
 *
 * Refuses to produce a pin from a manifest that declares more than one active
 * root: pinning is a decision about one identity, and silently picking one of
 * several would make the pin depend on array order.
 */
/**
 * Refuses verification with no anchor.
 *
 * Factored out because `acceptChain` has to establish the pin BEFORE it can
 * decide whether the state it was handed belongs to that pin — and reaching
 * into a missing pin to find out would throw a TypeError instead of the
 * refusal this contract names.
 */
function requirePin(pin) {
  if (!isPlainObject(pin) || typeof pin.issuer !== 'string' || typeof pin.root !== 'string') {
    fail(
      'NO_TRUST_ANCHOR',
      'A pinned root { issuer, root } is required. Verification without an anchor would trust ' +
        'whatever key history it was given, which is exactly what a trust registry prevents',
    )
  }
}

export function rootPinFromManifest(document) {
  const { manifest } = validateRegistryDocument(document)
  const roots = manifest.keys.filter((key) => key.use === 'trust-root' && key.status === 'ACTIVE')

  if (roots.length === 0) {
    fail('NO_TRUST_ANCHOR', 'The manifest declares no active trust root to pin')
  }
  if (roots.length > 1) {
    fail(
      'AMBIGUOUS_ROOT',
      `The manifest declares ${roots.length} active trust roots. A pin names one identity; ` +
        'choose it deliberately rather than by position',
    )
  }

  return { issuer: manifest.issuer, root: roots[0].thumbprint }
}

/**
 * Verifies a published trust-registry document against a pinned root.
 *
 * The pin is mandatory. A verifier with no anchor could only believe whatever
 * key list it was handed, which is the failure this whole layer exists to
 * remove — so there is no pinless mode, not even a permissive one.
 *
 * What is checked here is that THE PINNED ROOT signed this manifest. The root's
 * own declared status is reported, not used to reject: a manifest announcing
 * "this root is compromised" is signed by that root, because it is the only
 * identity a pinned verifier will listen to. Such an announcement is weak by
 * nature — whoever stole the key can also make it — and the recovery is a new
 * out-of-band pin, never a silent substitution.
 */
export function verifyManifest(document, { pin } = {}) {
  requirePin(pin)

  const { attestations, manifest, signatures } = validateRegistryDocument(document)

  if (manifest.issuer !== pin.issuer) {
    fail(
      'ISSUER_MISMATCH',
      `The manifest is issued by "${manifest.issuer}", but the pin names "${pin.issuer}"`,
    )
  }

  const pinned = signatures.find((entry) => entry.signer.thumbprint === pin.root)
  if (pinned === undefined) {
    fail(
      'ROOT_MISMATCH',
      'No signature on this manifest was made by the pinned root. Either it was issued by a ' +
        'different identity, or the root was substituted — both are refusals, never a prompt ' +
        'to accept the new one',
    )
  }

  if (!signatureVerifies(manifestInput(manifest), pinned.signer.publicKey, pinned.suite, pinned.signature)) {
    fail(
      'REGISTRY_SIGNATURE_INVALID',
      "The pinned root's signature does not verify over this manifest: it was altered after " +
        'signing, or it was not signed by that root',
    )
  }

  return {
    attestations,
    digest: manifestDigest(manifest),
    manifest,
    rootKeyId: pinned.signer.keyId,
    // The root's own lifecycle, reported rather than enforced (above).
    rootStatus: pinned.signer.status,
  }
}

/**
 * Accepts a chain of published manifests against a pin and, optionally, the
 * state a verifier already holds — the highest registry version it has seen and
 * that manifest's digest.
 *
 * This is where a privileged operator's ability to rewrite key history dies. A
 * manifest that verifies is not yet acceptable: it must be no older than what
 * this verifier already saw, must not be a second manifest at a version it
 * already holds, and must link to its predecessor by digest.
 *
 * `attestations` sit outside the signature and are never trusted here. A
 * publication reference cannot be signed by the document it points at — the
 * commit id does not exist until after the document is committed. An
 * attestation is therefore a POINTER, checkable by recomputing the digest of
 * whatever it leads to, and never evidence that a publication happened.
 */
export function acceptChain(documents, { pin, state = null } = {}) {
  requirePin(pin)

  if (!Array.isArray(documents) || documents.length === 0) {
    fail('INVALID_MANIFEST', 'acceptChain requires at least one trust-registry document')
  }

  // State is only meaningful relative to the anchor that produced it. A
  // verifier handed state from another trust domain would otherwise compare
  // version numbers across two unrelated histories and answer
  // REGISTRY_ROLLBACK — or accept — for a reason that has nothing to do with
  // either of them. Refusing names the real mistake instead.
  if (state !== null) {
    if (!isPlainObject(state) || typeof state.issuer !== 'string' || typeof state.root !== 'string') {
      fail(
        'NO_TRUST_ANCHOR',
        'The verifier state must record the { issuer, root } it was established under, so that ' +
          'it can be continued only under that same anchor',
      )
    }
    if (state.issuer !== pin.issuer) {
      fail(
        'ISSUER_MISMATCH',
        `The verifier state was established for issuer "${state.issuer}", but the pin names ` +
          `"${pin.issuer}". A history is continued under the anchor that produced it, never ` +
          'under another one',
      )
    }
    if (state.root !== pin.root) {
      fail(
        'ROOT_MISMATCH',
        'The verifier state was established under a different trust root than the pin names. ' +
          'Two roots are two histories, and their version numbers say nothing about each other',
      )
    }
  }

  let current = state === null ? null : { ...state }
  let accepted = null
  // The held watermark is fixed for the whole walk: only history below what
  // the verifier ALREADY held may be re-served without becoming current.
  const watermark = state === null ? null : state.registryVersion

  for (const document of documents) {
    const verified = verifyManifest(document, { pin })
    const { manifest, digest } = verified

    if (current !== null) {
      if (manifest.registryVersion < current.registryVersion) {
        // Below the HELD watermark only: a served full-history export
        // legitimately begins before the version this verifier already
        // holds (PRUVZ-97 conformance finding: refusing it here made every
        // re-verification of a multi-version chain a false ROLLBACK). The
        // document is still signature-verified above; it just cannot become
        // current. A document older than an EARLIER DOCUMENT OF THIS SERVED
        // CHAIN gets no such tolerance — a deployment serves its history in
        // order, and out-of-order documents whose linkage was never walked
        // must not be waved through as if it had been.
        if (watermark !== null && manifest.registryVersion < watermark) {
          continue
        }
        fail(
          'REGISTRY_ROLLBACK',
          `This manifest is registry version ${manifest.registryVersion}, but version ` +
            `${current.registryVersion} has already been seen. Presenting an older, still ` +
            'correctly signed manifest is how a revocation is hidden',
        )
      }
      if (manifest.registryVersion === current.registryVersion) {
        if (digest !== current.digest) {
          fail(
            'REGISTRY_FORK',
            `Two different manifests both claim registry version ${manifest.registryVersion}. ` +
              'One version has one history; this is a fork, and no rule can pick the honest side',
          )
        }
        accepted = verified
        continue
      }
      if (manifest.registryVersion !== current.registryVersion + 1) {
        fail(
          'REGISTRY_CHAIN_BROKEN',
          `Cannot step from registry version ${current.registryVersion} to ` +
            `${manifest.registryVersion}: the intervening manifests are missing, and skipping ` +
            'them would accept key history nobody checked',
        )
      }
      if (
        manifest.previous.registryVersion !== current.registryVersion ||
        manifest.previous.digest !== current.digest
      ) {
        fail(
          'REGISTRY_CHAIN_BROKEN',
          `Registry version ${manifest.registryVersion} does not link to the manifest this ` +
            'verifier holds: its predecessor digest names a different document',
        )
      }
    }

    current = {
      digest,
      issuer: manifest.issuer,
      registryVersion: manifest.registryVersion,
      root: pin.root,
    }
    accepted = verified
  }

  if (accepted === null) {
    fail(
      'REGISTRY_ROLLBACK',
      `Every served manifest is older than registry version ${current.registryVersion}, which ` +
        'this verifier has already accepted. Presenting an older, still correctly signed ' +
        'history as the present is how a revocation is hidden',
    )
  }

  const reasonCodes = []
  if (accepted.rootStatus === 'REVOKED') {
    reasonCodes.push('ROOT_REVOKED')
  } else if (accepted.rootStatus === 'RETIRED') {
    reasonCodes.push('ROOT_RETIRED')
  }

  return { ...accepted, reasonCodes, state: current }
}

/**
 * Resolves the key a seal names, inside a manifest that has already been
 * verified against a pin.
 */
export function resolveSigningKey(manifest, keyId) {
  const key = manifest.keys.find((candidate) => candidate.keyId === keyId)
  if (key === undefined) {
    return { key: null, reason: 'UNKNOWN_KEY' }
  }
  if (key.use !== 'evidence-signing') {
    return { key, reason: 'KEY_USE_MISMATCH' }
  }
  return { key, reason: null }
}

/**
 * The exact byte string an evidence seal's signature covers (product PRUVZ-94):
 *
 *   "pruvz.ai/evidence-signature" 0x00 version 0x00 <canonical JSON of envelope>
 *
 * Recomputed from the envelope, never taken from a transported copy. Verifying
 * bytes somebody handed over would verify their claim about the envelope rather
 * than the envelope — which is exactly why the product deliberately does not
 * return them.
 */
export function sealSigningInput(envelope) {
  if (!isPlainObject(envelope)) {
    fail('INVALID_MANIFEST', 'seal.envelope must be an object')
  }
  if (envelope.version !== SEAL_ENVELOPE_VERSION) {
    fail(
      'INVALID_MANIFEST',
      `Unknown evidence-envelope version ${
        envelope.version === undefined ? '(none)' : `"${envelope.version}"`
      }. This implementation speaks version ${SEAL_ENVELOPE_VERSION}.`,
    )
  }
  const header = [SEAL_DOMAIN_TAG, envelope.version, ''].join(HEADER_SEPARATOR)
  return Buffer.concat([Buffer.from(header, 'utf8'), canonicalize(envelope)])
}

/**
 * Verifies one evidence seal against a pinned, verified trust registry.
 *
 * The result is dimensional on purpose. "Is the signature valid?", "is this key
 * ours?", "was it trustworthy when it signed?", "is this a seal about this
 * record?" and "does it commit to this content?" are five questions, and
 * collapsing them into a boolean is how a partially verified record gets
 * reported as a verified one.
 *
 * `expectedCommitmentDigest` is optional and must be computed by the CALLER
 * from the record itself, never read out of the envelope. When it is absent the
 * content dimension is honestly NOT_CHECKED and the verdict can never be better
 * than PARTIAL: a seal whose digest nobody compared proves origin and binding,
 * not that the record still says what it said.
 */
export function verifySeal({
  seal,
  manifest,
  expectedSubject,
  expectedCommitmentDigest = null,
  registryReasonCodes = [],
} = {}) {
  if (!isPlainObject(seal) || !isPlainObject(seal.envelope)) {
    fail('INVALID_MANIFEST', 'seal must be { envelope, signature }')
  }
  if (!isPlainObject(manifest) || !Array.isArray(manifest.keys)) {
    fail('INVALID_MANIFEST', 'manifest must be a verified manifest from verifyManifest/acceptChain')
  }
  if (!isPlainObject(expectedSubject)) {
    fail(
      'INVALID_MANIFEST',
      'expectedSubject is required: a seal that is valid for some other record is still valid, ' +
        'so a verifier must always say which record it is asking about',
    )
  }

  const envelope = seal.envelope
  const dimensions = {
    content: 'NOT_CHECKED',
    keyIdentity: 'NOT_CHECKED',
    keyLifecycle: 'NOT_CHECKED',
    signature: 'NOT_CHECKED',
    subject: 'NOT_CHECKED',
  }
  const reasonCodes = [...registryReasonCodes]
  const invalid = (code) => {
    reasonCodes.push(code)
    return { dimensions, reasonCodes, verdict: 'INVALID' }
  }

  if (envelope.version !== SEAL_ENVELOPE_VERSION) {
    return invalid('UNKNOWN_ENVELOPE_VERSION')
  }

  const signerRef = envelope.signer
  if (!isPlainObject(signerRef) || typeof signerRef.keyId !== 'string') {
    return invalid('MALFORMED_ENVELOPE')
  }

  const { key, reason } = resolveSigningKey(manifest, signerRef.keyId)
  if (reason !== null) {
    return invalid(reason)
  }
  dimensions.keyIdentity = 'TRUSTED'

  // The envelope's own claims about the key must agree with the published key
  // history. They are inside the signature, so a mismatch is not tampering — it
  // is a signature made under a description of the key that the registry does
  // not recognize, which is a different key as far as a verifier is concerned.
  if (signerRef.suite !== key.suite) {
    return invalid('KEY_SUITE_MISMATCH')
  }
  if (signerRef.provider !== key.provider) {
    return invalid('KEY_PROVIDER_MISMATCH')
  }

  let signature
  try {
    signature = decodeBase64Url(seal.signature, 'seal.signature')
  } catch {
    return invalid('MALFORMED_SIGNATURE')
  }
  if (signature.length !== SUITES[key.suite].signatureLength) {
    return invalid('MALFORMED_SIGNATURE')
  }

  let signingInput
  try {
    signingInput = sealSigningInput(envelope)
  } catch {
    return invalid('MALFORMED_ENVELOPE')
  }

  if (!signatureVerifies(signingInput, key.publicKey, key.suite, signature)) {
    dimensions.signature = 'INVALID'
    return invalid('SIGNATURE_INVALID')
  }
  dimensions.signature = 'VALID'

  // Everything below is about what a valid signature attests to. Asking any of
  // it earlier would be reasoning about an unauthenticated document.
  if (typeof envelope.committedAt !== 'string') {
    return invalid('MALFORMED_ENVELOPE')
  }

  let stateWhenSigned
  try {
    stateWhenSigned = keyStateAt(key, envelope.committedAt)
  } catch {
    return invalid('MALFORMED_ENVELOPE')
  }
  dimensions.keyLifecycle = stateWhenSigned

  if (stateWhenSigned === 'NOT_YET_VALID') {
    return invalid('SIGNED_BEFORE_KEY_VALID')
  }
  if (stateWhenSigned === 'REVOKED') {
    return invalid('SIGNED_AFTER_REVOCATION')
  }
  if (stateWhenSigned === 'RETIRED') {
    return invalid('SIGNED_AFTER_RETIREMENT')
  }

  let weakened = reasonCodes.includes('ROOT_REVOKED')

  // The key was active when it signed. What happened to it later decides how
  // much that is worth.
  if (key.revokedAtUtc !== null) {
    // Signed before the declared compromise boundary. Worth something — but the
    // boundary is compared against a time PRUVZ ITSELF asserted, so a signer
    // that was already compromised could have back-dated it. An external
    // witness of the seal is what would settle that, and there is none yet.
    reasonCodes.push('SIGNED_BEFORE_REVOCATION', 'COMMITTED_AT_SELF_ASSERTED')
    weakened = true
  } else if (key.retiredAtUtc !== null) {
    // Ordinary rotation. It weakens nothing: the key was active, the signature
    // stands, and history survives the rotation exactly as it must.
    reasonCodes.push('KEY_RETIRED_AFTER_SIGNING')
  }

  const subject = envelope.subject
  if (
    !isPlainObject(subject) ||
    subject.tenantId !== expectedSubject.tenantId ||
    subject.actionId !== expectedSubject.actionId ||
    subject.evidenceId !== expectedSubject.evidenceId ||
    subject.sequence !== expectedSubject.sequence
  ) {
    dimensions.subject = 'MISMATCH'
    return invalid('SUBJECT_MISMATCH')
  }
  dimensions.subject = 'MATCHES'

  if (expectedCommitmentDigest === null) {
    reasonCodes.push('COMMITMENT_NOT_CHECKED')
    weakened = true
  } else if (envelope.commitment?.digest !== expectedCommitmentDigest) {
    dimensions.content = 'MISMATCH'
    return invalid('COMMITMENT_MISMATCH')
  } else {
    dimensions.content = 'MATCHES'
  }

  return { dimensions, reasonCodes, verdict: weakened ? 'PARTIAL' : 'VALID' }
}
