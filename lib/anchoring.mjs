// External anchoring — the reference implementation (docs/ANCHORING.md).
//
// Two things live here and they are deliberately unequal in weight:
//
//   1. The imprint derivation. This is a composition THIS contract defines, so
//      two runtimes must agree on it byte for byte or an anchor witnessed by
//      one cannot be checked by the other. The golden vectors pin it.
//   2. A reader for the RFC 3161 TimeStampToken that the derivation is checked
//      against. It reads; it does not verify. CMS signature verification and
//      X.509 path validation are published standards with maintained platform
//      implementations, and this repository does not hand-roll cryptography.
//
// docs/ANCHORING.md section 6 states that boundary in the terms a caller needs:
// establishing that a receipt is ABOUT a subject says nothing about whether the
// receipt is genuine, and an implementation that stops here is not a verifier.

import { createHash, randomBytes } from 'node:crypto'

import { canonicalize, canonicalTimestamp } from './canonical.mjs'
import { validateCheckpointDocument } from './evidence-log.mjs'

/** The anchoring format version this implementation speaks. */
export const ANCHORING_FORMAT_VERSION = '1'

/**
 * Domain-separation tags. Two more domains beside the commitment's, the
 * envelope's, the registry's, the leaf's and the checkpoint's: bytes hashed as
 * a checkpoint anchor can never be re-read as a registry anchor, and neither
 * can be re-read as anything else this contract hashes.
 */
export const SUBJECT_DOMAIN_TAGS = {
  'log-checkpoint': 'pruvz.ai/log-anchor',
  'trust-registry': 'pruvz.ai/trust-registry-anchor',
}

/** The subject kinds the format admits — aggregate documents only. */
export const SUBJECT_KINDS = Object.keys(SUBJECT_DOMAIN_TAGS)

/** The header field separator: a NUL byte, as everywhere else in this contract. */
const HEADER_SEPARATOR = '\u0000'

/** The blinding nonce is exactly this wide, which is why no separator follows it. */
export const BLINDING_NONCE_BYTES = 32

/** The shortest RFC 3161 request nonce this format will carry. */
export const MIN_REQUEST_NONCE_BYTES = 8

/** Anchor status. Explicit, never inferred from the presence of a receipt. */
export const ANCHOR_STATUSES = ['ANCHORED', 'PENDING', 'FAILED']

/** The only receipt kind this version defines. */
export const RECEIPT_KIND = 'rfc3161-timestamp-token'

/** The longest a single bound string may be, matching every other layer. */
const MAX_BOUND_TEXT_LENGTH = 512

/** 2^53 - 1: the largest integer the canonical JSON layer can carry. */
const MAX_SAFE_INTEGER = 9007199254740991

/**
 * Everything this implementation can refuse, by stable code. The last two are
 * part of the format's vocabulary but belong to half two of section 6 — an
 * implementation that validates the authority produces them; this one cannot,
 * and never returns a result that implies it did.
 */
export const REFUSAL_CODES = [
  'UNKNOWN_ANCHOR_VERSION', // a version this implementation does not speak
  'ANCHOR_MALFORMED', // a record that is not what the format allows
  'ANCHOR_RECEIPT_MALFORMED', // a token that is not a well-formed TimeStampToken
  'ANCHOR_SUITE_UNSUPPORTED', // a messageImprint under an algorithm this format does not define
  'ANCHOR_BINDING_MISMATCH', // the token is not about this subject under this nonce
  'ANCHOR_NONCE_MISMATCH', // the token's nonce is not the record's requestNonce
  'ANCHOR_NOT_PRESENT', // an anchor was required and this one is pending or failed
  'ANCHOR_SIGNATURE_INVALID', // half two: the token's signature does not verify
  'ANCHOR_UNTRUSTED_AUTHORITY', // half two: EKU, validity at genTime, chain, or policy
]

export class AnchorError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'AnchorError'
    this.code = code
  }
}

const fail = (code, message) => {
  throw new AnchorError(code, message)
}

const isPlainObject = (value) =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const sha256 = (...parts) => {
  const hash = createHash('sha256')
  for (const part of parts) {
    hash.update(part)
  }
  return hash.digest()
}

/**
 * A string that may appear in an anchor record: non-empty, bounded, printable
 * ASCII — the rule the envelope, the checkpoint and the manifest all apply, so
 * that any runtime reproduces the bytes exactly and the NUL header separator
 * can never occur inside a value.
 */
const boundText = (value, field) => {
  if (typeof value !== 'string' || value.length === 0) {
    fail('ANCHOR_MALFORMED', `${field} is required`)
  }
  if (value.length > MAX_BOUND_TEXT_LENGTH) {
    fail('ANCHOR_MALFORMED', `${field} must not exceed ${MAX_BOUND_TEXT_LENGTH} characters`)
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    fail('ANCHOR_MALFORMED', `${field} must be printable ASCII`)
  }
  return value
}

/**
 * Strict canonical unpadded base64url, the rule every signature in this
 * contract follows: the decoded bytes must re-encode to exactly the text
 * received, so one value has exactly one transported spelling.
 */
const decodeBase64Url = (value, field) => {
  if (typeof value !== 'string' || value === '' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail('ANCHOR_MALFORMED', `${field} must be unpadded base64url`)
  }
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.toString('base64url') !== value) {
    fail('ANCHOR_MALFORMED', `${field} is not a canonical unpadded base64url encoding`)
  }
  return bytes
}

/**
 * Strict standard base64, used for the DER token only — a token is bytes from
 * an authority rather than a value this contract mints, and base64 is how
 * RFC 3161 tokens are conventionally transported.
 */
const decodeBase64 = (value, field) => {
  if (typeof value !== 'string' || value === '' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail('ANCHOR_RECEIPT_MALFORMED', `${field} must be base64`)
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.toString('base64') !== value) {
    fail('ANCHOR_RECEIPT_MALFORMED', `${field} is not a canonical base64 encoding`)
  }
  return bytes
}

/**
 * The unsigned big-endian value of an INTEGER's content octets, with leading
 * zero bytes removed.
 *
 * DER prepends a 0x00 to an INTEGER whose high bit is set, so the same nonce
 * can appear as 32 bytes in one encoding and 33 in another. Comparing raw
 * content octets would make a correct token look like a nonce mismatch roughly
 * half the time, which is a bug that only shows up in production. Both sides
 * are normalized to the same unsigned value instead.
 */
const unsignedValue = (bytes) => {
  let start = 0
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start += 1
  }
  return bytes.subarray(start)
}

/** A fresh 32-byte blinding nonce. Allocated once per anchor and never regenerated. */
export const newBlindingNonce = () => randomBytes(BLINDING_NONCE_BYTES)

/** A fresh RFC 3161 request nonce. Chosen again for every request, including retries. */
export const newRequestNonce = (bytes = 16) => {
  if (!Number.isInteger(bytes) || bytes < MIN_REQUEST_NONCE_BYTES) {
    fail('ANCHOR_MALFORMED', `a request nonce is at least ${MIN_REQUEST_NONCE_BYTES} bytes`)
  }
  // The high bit is cleared so the value is unambiguously positive as a DER
  // INTEGER, and its minimal unsigned encoding is the bytes themselves.
  const nonce = randomBytes(bytes)
  nonce[0] &= 0x7f
  if (nonce[0] === 0) {
    nonce[0] = 1
  }
  return nonce
}

/**
 * Refuses an anchoring format version this implementation cannot speak, before
 * any byte of the record is trusted — the rule every other layer applies to its
 * own version.
 */
export function requireSupported(formatVersion) {
  if (formatVersion !== ANCHORING_FORMAT_VERSION) {
    fail(
      'UNKNOWN_ANCHOR_VERSION',
      `Unknown anchoring version ${
        formatVersion === undefined ? '(none)' : `"${formatVersion}"`
      }. This implementation speaks version ${ANCHORING_FORMAT_VERSION}.`,
    )
  }
}

// ---------------------------------------------------------------------------
// Subjects
// ---------------------------------------------------------------------------

/**
 * The canonical bytes of a subject, and the identity the record must agree
 * with. Only aggregate documents are admissible: a checkpoint covers every
 * leaf beneath it, and a manifest is a key history — neither has a tenant, an
 * action or a payload member to leak.
 *
 * A trust-registry subject is derived from the published document by taking
 * exactly `{ manifest, signatures }`. `attestations` is excluded because it is
 * where the receipt lands: a subject that included it could never be
 * witnessed, since the bytes would have to contain a receipt that does not yet
 * exist. Callers may therefore pass the whole document.
 */
export function subjectMaterial(kind, subject) {
  if (!Object.hasOwn(SUBJECT_DOMAIN_TAGS, kind)) {
    fail('ANCHOR_MALFORMED', `subject.kind "${kind}" is not a subject this format anchors`)
  }
  if (!isPlainObject(subject)) {
    fail('ANCHOR_MALFORMED', 'a subject must be an object')
  }

  if (kind === 'log-checkpoint') {
    const unknown = Object.keys(subject).filter(
      (member) => member !== 'checkpoint' && member !== 'signature',
    )
    if (unknown.length > 0) {
      fail(
        'ANCHOR_MALFORMED',
        `a log-checkpoint subject holds exactly checkpoint and signature; got ${unknown.join(', ')}`,
      )
    }
    if (!isPlainObject(subject.checkpoint)) {
      fail('ANCHOR_MALFORMED', 'a log-checkpoint subject must carry a checkpoint object')
    }
    try {
      validateCheckpointDocument(subject.checkpoint)
    } catch (error) {
      // The evidence-log layer's refusal vocabulary never leaks out of this
      // format's: a checkpoint this format cannot anchor is a malformed
      // subject here, whatever it is over there.
      fail('ANCHOR_MALFORMED', `the checkpoint being anchored is not valid: ${error.message}`)
    }
    decodeBase64Url(subject.signature, 'subject.signature')
    return {
      document: { checkpoint: subject.checkpoint, signature: subject.signature },
      origin: subject.checkpoint.origin,
      subjectVersion: subject.checkpoint.checkpointSequence,
    }
  }

  if (!isPlainObject(subject.manifest)) {
    fail('ANCHOR_MALFORMED', 'a trust-registry subject must carry a manifest object')
  }
  if (!Array.isArray(subject.signatures) || subject.signatures.length === 0) {
    fail('ANCHOR_MALFORMED', 'a trust-registry subject must carry a non-empty signatures array')
  }
  const { issuer, registryVersion } = subject.manifest
  boundText(issuer, 'subject.manifest.issuer')
  if (!Number.isInteger(registryVersion) || registryVersion < 1) {
    fail('ANCHOR_MALFORMED', 'subject.manifest.registryVersion must be a positive integer')
  }
  return {
    document: { manifest: subject.manifest, signatures: subject.signatures },
    origin: issuer,
    subjectVersion: registryVersion,
  }
}

/**
 * The exact byte string an imprint is taken over:
 *
 *   <domain tag> 0x00 <version> 0x00 <32 raw nonce bytes> <canonical JSON of the subject>
 *
 * The header is UTF-8 text; the nonce is 32 RAW bytes, not text. No separator
 * follows the nonce because its width is fixed by this format — a format
 * admitting a variable-width nonce would need one, and this one may not become
 * that format without a new version.
 */
export function anchorInput(kind, blindingNonce, subject) {
  const material = subjectMaterial(kind, subject)
  const nonce = Buffer.isBuffer(blindingNonce) ? blindingNonce : decodeBase64Url(blindingNonce, 'blindingNonce')
  if (nonce.length !== BLINDING_NONCE_BYTES) {
    fail(
      'ANCHOR_MALFORMED',
      `a blinding nonce is exactly ${BLINDING_NONCE_BYTES} bytes; got ${nonce.length}`,
    )
  }
  const header = [SUBJECT_DOMAIN_TAGS[kind], ANCHORING_FORMAT_VERSION, ''].join(HEADER_SEPARATOR)
  let body
  try {
    body = canonicalize(material.document)
  } catch (error) {
    fail('ANCHOR_MALFORMED', `a subject cannot be canonicalized: ${error.message}`)
  }
  return Buffer.concat([Buffer.from(header, 'utf8'), nonce, body])
}

/**
 * The 32 bytes that cross the boundary, and the only value derived from a
 * subject that ever does. Not the subject, not the nonce, not the origin:
 * the authority receives this and the request nonce, and no third value.
 */
export function anchorImprint(kind, blindingNonce, subject) {
  return sha256(anchorInput(kind, blindingNonce, subject))
}

// ---------------------------------------------------------------------------
// The anchor record
// ---------------------------------------------------------------------------

const RECORD_MEMBERS = [
  'anchorId',
  'blindingNonce',
  'receipt',
  'requestNonce',
  'status',
  'subject',
  'trustDomain',
  'version',
]

const SUBJECT_MEMBERS = ['kind', 'origin', 'subjectVersion']

const RECEIPT_MEMBERS = ['kind', 'token']

/**
 * Validates an anchor record — the sidecar that lets a verifier check the
 * binding. It is not signed by Pruvz and does not need to be: everything it
 * asserts is either checkable against the authority's token or is inert.
 *
 * The record deliberately carries no imprint, no witness time, no policy
 * identifier and no authority name. All four are inside the token, and a
 * second copy outside it is a value a verifier could read INSTEAD of checking.
 */
export function validateAnchorRecord(record) {
  if (!isPlainObject(record)) {
    fail('ANCHOR_MALFORMED', 'an anchor record must be an object')
  }
  requireSupported(record.version)

  const unknown = Object.keys(record).filter((member) => !RECORD_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail('ANCHOR_MALFORMED', `an anchor record carries ${unknown.join(', ')}; the member set is closed`)
  }
  const missing = RECORD_MEMBERS.filter((member) => !(member in record))
  if (missing.length > 0) {
    fail('ANCHOR_MALFORMED', `an anchor record is missing ${missing.join(', ')}`)
  }

  boundText(record.anchorId, 'anchorId')
  boundText(record.trustDomain, 'trustDomain')

  if (!ANCHOR_STATUSES.includes(record.status)) {
    fail('ANCHOR_MALFORMED', `status must be one of ${ANCHOR_STATUSES.join(', ')}`)
  }

  if (!isPlainObject(record.subject)) {
    fail('ANCHOR_MALFORMED', 'subject must be an object')
  }
  const subjectUnknown = Object.keys(record.subject).filter(
    (member) => !SUBJECT_MEMBERS.includes(member),
  )
  if (subjectUnknown.length > 0) {
    fail(
      'ANCHOR_MALFORMED',
      `subject carries ${subjectUnknown.join(', ')}; it holds exactly ${SUBJECT_MEMBERS.join(', ')}`,
    )
  }
  if (!SUBJECT_KINDS.includes(record.subject.kind)) {
    fail('ANCHOR_MALFORMED', `subject.kind must be one of ${SUBJECT_KINDS.join(', ')}`)
  }
  boundText(record.subject.origin, 'subject.origin')
  if (
    !Number.isInteger(record.subject.subjectVersion) ||
    record.subject.subjectVersion < 1 ||
    record.subject.subjectVersion > MAX_SAFE_INTEGER
  ) {
    fail('ANCHOR_MALFORMED', 'subject.subjectVersion must be a positive integer')
  }

  const blindingNonce = decodeBase64Url(record.blindingNonce, 'blindingNonce')
  if (blindingNonce.length !== BLINDING_NONCE_BYTES) {
    fail(
      'ANCHOR_MALFORMED',
      `blindingNonce is ${blindingNonce.length} bytes; it is exactly ${BLINDING_NONCE_BYTES}`,
    )
  }
  const requestNonce = decodeBase64Url(record.requestNonce, 'requestNonce')
  if (requestNonce.length < MIN_REQUEST_NONCE_BYTES) {
    fail(
      'ANCHOR_MALFORMED',
      `requestNonce is ${requestNonce.length} bytes; at least ${MIN_REQUEST_NONCE_BYTES} are required`,
    )
  }

  // Status decides whether a receipt may exist. A record that is not ANCHORED
  // and carries a receipt is incoherent rather than helpful: it invites a
  // reader to conclude from the receipt's presence what the status denies.
  if (record.status === 'ANCHORED') {
    if (!isPlainObject(record.receipt)) {
      fail('ANCHOR_MALFORMED', 'an ANCHORED record must carry a receipt')
    }
    const receiptUnknown = Object.keys(record.receipt).filter(
      (member) => !RECEIPT_MEMBERS.includes(member),
    )
    if (receiptUnknown.length > 0) {
      fail('ANCHOR_MALFORMED', `receipt carries ${receiptUnknown.join(', ')}; it holds exactly kind, token`)
    }
    if (record.receipt.kind !== RECEIPT_KIND) {
      fail('ANCHOR_MALFORMED', `receipt.kind must be "${RECEIPT_KIND}"`)
    }
    if (typeof record.receipt.token !== 'string' || record.receipt.token.length === 0) {
      fail('ANCHOR_MALFORMED', 'receipt.token is required')
    }
  } else if (record.receipt !== null) {
    fail('ANCHOR_MALFORMED', `a ${record.status} record must carry receipt: null`)
  }

  return { blindingNonce, requestNonce }
}

// ---------------------------------------------------------------------------
// Reading an RFC 3161 TimeStampToken
//
// A DER walker, not a verifier. It exists so that half one of section 6 can be
// checked in any runtime: the messageImprint, the nonce, the genTime and the
// policy are read out of the token so the binding can be compared. Nothing
// here establishes that the token is genuine, and no caller may treat a
// successful read as a verified anchor.
// ---------------------------------------------------------------------------

const TAG_INTEGER = 0x02
const TAG_OCTET_STRING = 0x04
const TAG_NULL = 0x05
const TAG_OID = 0x06
const TAG_SEQUENCE = 0x30
const TAG_SET = 0x31
const TAG_GENERALIZED_TIME = 0x18

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'
const OID_SHA256 = '2.16.840.1.101.3.4.2.1'

/** The digest algorithms a messageImprint may name. One, deliberately. */
const IMPRINT_ALGORITHMS = { [OID_SHA256]: 'sha-256' }

const derFail = (message) => fail('ANCHOR_RECEIPT_MALFORMED', message)

/**
 * Reads one tag-length-value at `offset`. Definite lengths only: an indefinite
 * length is BER, not DER, and a token that used one would be a token this
 * implementation cannot fully read.
 */
const readTlv = (buffer, offset) => {
  if (offset + 2 > buffer.length) {
    derFail('the token ends inside a tag header')
  }
  const tag = buffer[offset]
  let cursor = offset + 1
  let length = buffer[cursor]
  cursor += 1
  if (length === 0x80) {
    derFail('indefinite lengths are BER, not DER')
  }
  if (length & 0x80) {
    const count = length & 0x7f
    if (count > 4) {
      derFail('a length this implementation cannot read')
    }
    if (cursor + count > buffer.length) {
      derFail('the token ends inside a length')
    }
    length = 0
    for (let i = 0; i < count; i += 1) {
      length = length * 256 + buffer[cursor]
      cursor += 1
    }
  }
  const end = cursor + length
  if (end > buffer.length) {
    derFail('a value extends past the end of the token')
  }
  return { tag, value: buffer.subarray(cursor, end), end }
}

const expect = (buffer, offset, tag, what) => {
  const tlv = readTlv(buffer, offset)
  if (tlv.tag !== tag) {
    derFail(`expected ${what}`)
  }
  return tlv
}

/** An OBJECT IDENTIFIER in dotted form, from its base-128 content octets. */
const readOid = (bytes) => {
  if (bytes.length === 0) {
    derFail('an empty object identifier')
  }
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40]
  let value = 0
  let started = false
  for (let i = 1; i < bytes.length; i += 1) {
    const byte = bytes[i]
    value = value * 128 + (byte & 0x7f)
    started = true
    if ((byte & 0x80) === 0) {
      parts.push(value)
      value = 0
      started = false
    }
  }
  if (started) {
    derFail('an object identifier that ends mid-value')
  }
  return parts.join('.')
}

/**
 * A GeneralizedTime as a canonical UTC timestamp. RFC 3161 requires the Zulu
 * form; a local-time or offset form is a token this implementation refuses
 * rather than guesses at.
 */
const readGeneralizedTime = (bytes) => {
  const text = bytes.toString('ascii')
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text)
  if (match === null) {
    derFail(`genTime "${text}" is not a UTC GeneralizedTime`)
  }
  const [, year, month, day, hour, minute, second, fraction] = match
  const iso = `${year}-${month}-${day}T${hour}:${minute}:${second}${
    fraction === undefined ? '' : `.${fraction}`
  }Z`
  try {
    return canonicalTimestamp(iso)
  } catch (error) {
    derFail(`genTime is not a valid instant: ${error.message}`)
  }
}

/**
 * Extracts what half one of section 6 needs from a TimeStampToken: the
 * messageImprint, the nonce, the genTime and the policy.
 *
 * This does NOT verify the token. It does not check the signature, the
 * certificate chain, the extended key usage, the certificate's validity at
 * genTime or the policy against a pinned configuration — section 6 half two,
 * which belongs to a platform CMS and X.509 implementation. A successful read
 * means the bytes parse, and means nothing whatever about trust.
 */
export function readTimestampToken(der) {
  const bytes = Buffer.isBuffer(der) ? der : decodeBase64(der, 'receipt.token')

  const contentInfo = expect(bytes, 0, TAG_SEQUENCE, 'a ContentInfo SEQUENCE')
  if (contentInfo.end !== bytes.length) {
    derFail('trailing bytes after the ContentInfo')
  }
  const body = contentInfo.value

  const contentType = expect(body, 0, TAG_OID, 'the ContentInfo contentType')
  if (readOid(contentType.value) !== OID_SIGNED_DATA) {
    derFail('the token is not a CMS SignedData')
  }
  const explicitContent = readTlv(body, contentType.end)
  if (explicitContent.tag !== 0xa0) {
    derFail('the SignedData content is not [0] EXPLICIT')
  }
  const signedData = expect(explicitContent.value, 0, TAG_SEQUENCE, 'a SignedData SEQUENCE')

  // version, then digestAlgorithms, then the encapsulated content.
  const version = expect(signedData.value, 0, TAG_INTEGER, 'the SignedData version')
  const digestAlgorithms = expect(signedData.value, version.end, TAG_SET, 'the digestAlgorithms SET')
  const encap = expect(
    signedData.value,
    digestAlgorithms.end,
    TAG_SEQUENCE,
    'an EncapsulatedContentInfo SEQUENCE',
  )

  const eContentType = expect(encap.value, 0, TAG_OID, 'the eContentType')
  if (readOid(eContentType.value) !== OID_TST_INFO) {
    derFail('the encapsulated content is not a TSTInfo')
  }
  const eContent = readTlv(encap.value, eContentType.end)
  if (eContent.tag !== 0xa0) {
    derFail('the eContent is not [0] EXPLICIT')
  }
  const octets = expect(eContent.value, 0, TAG_OCTET_STRING, 'the TSTInfo OCTET STRING')
  const tstInfo = expect(octets.value, 0, TAG_SEQUENCE, 'a TSTInfo SEQUENCE')
  const info = tstInfo.value

  const tstVersion = expect(info, 0, TAG_INTEGER, 'the TSTInfo version')
  const policy = expect(info, tstVersion.end, TAG_OID, 'the TSTInfo policy')
  const messageImprint = expect(info, policy.end, TAG_SEQUENCE, 'the messageImprint')

  const algorithmIdentifier = expect(
    messageImprint.value,
    0,
    TAG_SEQUENCE,
    'the messageImprint hashAlgorithm',
  )
  const algorithmOid = expect(algorithmIdentifier.value, 0, TAG_OID, 'the hashAlgorithm OID')
  // The parameters, when present, must be absent-or-NULL for the hashes this
  // format defines; anything else is an algorithm variant we did not read.
  if (algorithmOid.end !== algorithmIdentifier.value.length) {
    const parameters = readTlv(algorithmIdentifier.value, algorithmOid.end)
    if (parameters.tag !== TAG_NULL || parameters.end !== algorithmIdentifier.value.length) {
      derFail('a hashAlgorithm carrying parameters this implementation does not read')
    }
  }
  const hashedMessage = expect(
    messageImprint.value,
    algorithmIdentifier.end,
    TAG_OCTET_STRING,
    'the hashedMessage',
  )
  if (hashedMessage.end !== messageImprint.value.length) {
    derFail('trailing bytes inside the messageImprint')
  }

  const serialNumber = expect(info, messageImprint.end, TAG_INTEGER, 'the serialNumber')
  const genTimeTlv = expect(info, serialNumber.end, TAG_GENERALIZED_TIME, 'the genTime')

  // accuracy, ordering, nonce, tsa and extensions are all optional and all
  // carry distinct tags, so the tail is read by dispatch rather than by
  // position. An unknown tag is a token shape this implementation cannot claim
  // to have read.
  let nonce = null
  let cursor = genTimeTlv.end
  while (cursor < info.length) {
    const next = readTlv(info, cursor)
    if (next.tag === TAG_INTEGER) {
      nonce = unsignedValue(next.value)
    } else if (
      next.tag !== TAG_SEQUENCE && // accuracy
      next.tag !== 0x01 && // ordering BOOLEAN
      next.tag !== 0xa0 && // [0] tsa
      next.tag !== 0xa1 // [1] extensions
    ) {
      derFail(`an unexpected TSTInfo member (tag 0x${next.tag.toString(16)})`)
    }
    cursor = next.end
  }

  return {
    policyOid: readOid(policy.value),
    messageImprint: {
      algorithmOid: readOid(algorithmOid.value),
      algorithm: IMPRINT_ALGORITHMS[readOid(algorithmOid.value)] ?? null,
      hash: Buffer.from(hashedMessage.value),
    },
    nonce,
    genTime: readGeneralizedTime(genTimeTlv.value),
  }
}

// ---------------------------------------------------------------------------
// Verification — half one only
// ---------------------------------------------------------------------------

/**
 * Checks that a receipt is ABOUT this subject: the imprint derived from the
 * subject and the record's blinding nonce is the one inside the token, and the
 * token answers the request the record names.
 *
 * This is half one of section 6 and it is not verification. The returned
 * `authorityVerified: false` says so in the result itself, so a caller cannot
 * pass this object on as though trust had been established: the signature, the
 * extended key usage, the certificate's validity at genTime, the chain to a
 * pinned root and the policy are all still unchecked, and an implementation
 * that stops here has established arithmetic rather than trust.
 */
export function verifyAnchorBinding({ record, subject } = {}) {
  const { blindingNonce, requestNonce } = validateAnchorRecord(record)

  if (record.status !== 'ANCHORED') {
    fail(
      'ANCHOR_NOT_PRESENT',
      `this anchor is ${record.status}; a subject without a witnessed anchor is never fully verified`,
    )
  }

  const material = subjectMaterial(record.subject.kind, subject)
  // The record's declared identity must be the identity of the document it is
  // checked against. Without this a record could name one checkpoint while its
  // imprint covered another, and every lookup that trusted the record would be
  // pointing at the wrong subject.
  if (material.origin !== record.subject.origin) {
    fail(
      'ANCHOR_MALFORMED',
      `this record names origin "${record.subject.origin}"; the subject is from "${material.origin}"`,
    )
  }
  if (material.subjectVersion !== record.subject.subjectVersion) {
    fail(
      'ANCHOR_MALFORMED',
      `this record names version ${record.subject.subjectVersion}; the subject is version ${material.subjectVersion}`,
    )
  }

  const imprint = anchorImprint(record.subject.kind, blindingNonce, subject)
  const token = readTimestampToken(record.receipt.token)

  if (token.messageImprint.algorithm === null) {
    fail(
      'ANCHOR_SUITE_UNSUPPORTED',
      `the token's messageImprint uses ${token.messageImprint.algorithmOid}, which this format does not define`,
    )
  }
  if (
    token.messageImprint.hash.length !== imprint.length ||
    !token.messageImprint.hash.equals(imprint)
  ) {
    fail(
      'ANCHOR_BINDING_MISMATCH',
      'the token witnesses a different imprint than this subject and blinding nonce produce',
    )
  }
  if (token.nonce === null) {
    fail('ANCHOR_NONCE_MISMATCH', 'the token carries no nonce; this record names one')
  }
  if (!token.nonce.equals(unsignedValue(requestNonce))) {
    fail('ANCHOR_NONCE_MISMATCH', 'the token answers a different request than this record names')
  }

  return {
    subject: { ...record.subject },
    trustDomain: record.trustDomain,
    anchorId: record.anchorId,
    imprint: imprint.toString('hex'),
    genTime: token.genTime,
    policyOid: token.policyOid,
    // Stated in the result, not only in the documentation: this function
    // checked the binding and nothing about the authority.
    authorityVerified: false,
  }
}
