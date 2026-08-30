// Reference implementation of the Pruvz append-only evidence log, format
// version 1: leaf encoding, Merkle tree composition, inclusion and consistency
// proofs, and signed checkpoints.
//
// A signed envelope (product PRUVZ-94, docs/TRUST-REGISTRY.md) answers "who
// committed to this record?". It cannot answer "and is the record still
// there?" — deleting a sealed record leaves every other seal verifying
// perfectly. The evidence log closes that gap: every seal is appended as a
// leaf of a Merkle tree, the tree head is periodically signed as a checkpoint,
// and a verifier holding checkpoint history can then detect deletion,
// insertion, reordering and forked history cryptographically.
//
// The tree composition is the one published for Certificate Transparency
// (RFC 6962 section 2.1; RFC 9162 section 2.1): leaves are hashed under a 0x00
// prefix, interior nodes under 0x01, and the inclusion/consistency proof
// algorithms are exactly the published ones. This is a deliberate reuse of a
// documented construction — it is NOT a claim that Pruvz implements the CT
// protocol, its log entries, or its APIs. What goes INTO a leaf is
// Pruvz-specific and domain-separated like every other layer of this contract.
//
// Two honest limits, stated here because they are easy to over-claim:
//
//   1. A checkpoint's `issuedAt` is self-asserted, exactly like a seal's
//      `committedAt`. External witnessing of checkpoints is a later capability
//      (product PRUVZ-96) and nothing here may be described as anchored.
//   2. The log preserves history; it does not make recorded facts true, and it
//      only covers records that were sealed into it. Capture fidelity is the
//      product's independent read-back, a separate assurance dimension.
//
// This file is the second-runtime reference for the .NET implementation in
// pruvz-core. Neither is authoritative alone: both must reproduce the published
// golden vectors in evidence-log/v1/golden-vectors.json.
import { createHash, createPublicKey, verify as verifyEcdsa } from 'node:crypto'

import { canonicalTimestamp, canonicalize } from './canonical.mjs'
import { SUITES } from './trust-registry.mjs'

/** The evidence-log format this implementation speaks. */
export const EVIDENCE_LOG_FORMAT_VERSION = '1'

/** The evidence-envelope format a leaf may carry (product PRUVZ-94). */
export const LEAF_ENVELOPE_VERSION = '1'

/**
 * Domain-separation tags. Two more domains beside the commitment's
 * ("pruvz.ai/commitment"), the envelope's ("pruvz.ai/evidence-signature") and
 * the registry's ("pruvz.ai/trust-registry"): bytes hashed as a leaf can never
 * be re-read as any of those, and checkpoint signing input can never collide
 * with a seal's.
 */
export const LEAF_DOMAIN_TAG = 'pruvz.ai/evidence-log-leaf'
export const CHECKPOINT_DOMAIN_TAG = 'pruvz.ai/log-checkpoint'

/** The header field separator: a NUL byte, as everywhere else in this contract. */
const HEADER_SEPARATOR = '\u0000'

/**
 * The RFC 6962 hashing prefixes. One byte before the data decides whether a
 * hash is a leaf hash or an interior-node hash, so a leaf can never be
 * presented as a subtree (the "second preimage" confusion the prefixes exist
 * to prevent).
 */
export const LEAF_HASH_PREFIX = 0x00
export const NODE_HASH_PREFIX = 0x01

/**
 * The assurance profiles a checkpoint may declare — the same closed set an
 * envelope declares, because a checkpoint states the profile that was actually
 * in force when it was issued, never a stronger one.
 */
export const ASSURANCE_PROFILES = ['PRE_CUSTOMER_DEFAULT', 'CUSTOMER_PRODUCTION']

/** The longest a single bound string may be, matching the envelope's rule. */
const MAX_BOUND_TEXT_LENGTH = 512

/** 2^53 - 1: the largest integer the canonical JSON layer can carry. */
const MAX_SAFE_INTEGER = 9007199254740991

/**
 * Everything this implementation can refuse, by stable code. The codes are
 * part of the format: the .NET implementation must refuse the same input with
 * the same code, which is what the golden vectors assert.
 */
export const REFUSAL_CODES = [
  // format
  'UNKNOWN_LOG_VERSION', // a version this implementation does not speak
  'LOG_MALFORMED', // a document that is not what the format allows
  'MALFORMED_SIGNATURE', // a signature that is not valid base64url of the suite's width
  'INVALID_PUBLIC_KEY', // a key that is not a valid public JWK for a known suite
  // proofs
  'INCLUSION_PROOF_INVALID', // the path does not lead this leaf to this root at this size
  'CONSISTENCY_PROOF_INVALID', // the proof does not show the new tree extends the old one
  // checkpoints
  'CHECKPOINT_SIGNATURE_INVALID', // the signature over the checkpoint does not verify
  'CHECKPOINT_STALE', // a checkpoint older than one already accepted, presented as current
  'CHECKPOINT_FORK', // two correctly signed checkpoints that contradict each other
  'CHECKPOINT_ROLLBACK', // a later checkpoint whose tree is smaller — append-only violated
  'CHECKPOINT_ORIGIN_MISMATCH', // a checkpoint from a different log entirely
]

export class EvidenceLogError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'EvidenceLogError'
    this.code = code
  }
}

const fail = (code, message) => {
  throw new EvidenceLogError(code, message)
}

const isPlainObject = (value) =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Canonicalizes a document that is about to be hashed or signed, translating
 * any canonicalization refusal (a non-safe integer, a malformed money value —
 * the canonical layer's own vocabulary) into this format's LOG_MALFORMED: one
 * layer, one set of refusal codes, whatever failed underneath.
 */
const canonicalBytes = (document, context) => {
  try {
    return canonicalize(document)
  } catch (error) {
    if (error instanceof EvidenceLogError) {
      throw error
    }
    fail('LOG_MALFORMED', `${context} cannot be canonicalized: ${error.message}`)
  }
}

const sha256 = (...parts) => {
  const hash = createHash('sha256')
  for (const part of parts) {
    hash.update(part)
  }
  return hash.digest()
}

const HEX = /^[0-9a-f]{64}$/

/** A SHA-256 value in the form the vectors and proofs carry: 64 lowercase hex digits. */
const hashFromHex = (value, field) => {
  if (typeof value !== 'string' || !HEX.test(value)) {
    fail('LOG_MALFORMED', `${field} must be 64 lowercase hex digits of SHA-256`)
  }
  return Buffer.from(value, 'hex')
}

/**
 * The `rootHash` field of a checkpoint names its suite explicitly —
 * "sha256:" then 64 lowercase hex digits — for the same reason a commitment
 * digest does: a future suite must be a recorded decision, never a default.
 */
const ROOT_HASH = /^sha256:[0-9a-f]{64}$/

export const rootHashText = (hash) => `sha256:${Buffer.from(hash).toString('hex')}`

const decodeBase64Url = (value, field) => {
  if (typeof value !== 'string' || value === '' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    fail('MALFORMED_SIGNATURE', `${field} must be unpadded base64url`)
  }
  const bytes = Buffer.from(value, 'base64url')
  // Strict: the decoded bytes must re-encode to the original text, so two
  // spellings of one signature cannot both be accepted. Node's decoder is
  // otherwise lenient about the unused low bits of a final character and about
  // a trailing character that carries no whole byte at all.
  if (bytes.toString('base64url') !== value) {
    fail('MALFORMED_SIGNATURE', `${field} is not a canonical unpadded base64url encoding`)
  }
  return bytes
}

/**
 * A string that may be bound into a checkpoint: non-empty, bounded, printable
 * ASCII only — the envelope's rule, for the envelope's reason: any runtime
 * that can sort object members and concatenate strings must reproduce the
 * signed bytes exactly, and the NUL header separator must never occur in a
 * bound value.
 */
const boundText = (value, field) => {
  if (typeof value !== 'string' || value.length === 0) {
    fail('LOG_MALFORMED', `${field} is required`)
  }
  if (value.length > MAX_BOUND_TEXT_LENGTH) {
    fail('LOG_MALFORMED', `${field} must not exceed ${MAX_BOUND_TEXT_LENGTH} characters`)
  }
  if (!/^[\x20-\x7e]+$/.test(value)) {
    fail('LOG_MALFORMED', `${field} must be printable ASCII`)
  }
  return value
}

const safePositiveInteger = (value, field) => {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > MAX_SAFE_INTEGER) {
    fail('LOG_MALFORMED', `${field} must be an integer between 1 and ${MAX_SAFE_INTEGER}`)
  }
  return value
}

/**
 * Refuses a log format version this implementation cannot speak, before any
 * byte of it is trusted — the same rule every other layer of this contract
 * applies to its own version.
 */
export function requireSupported(formatVersion) {
  if (formatVersion !== EVIDENCE_LOG_FORMAT_VERSION) {
    fail(
      'UNKNOWN_LOG_VERSION',
      `Unknown evidence-log version ${
        formatVersion === undefined ? '(none)' : `"${formatVersion}"`
      }. This implementation speaks version ${EVIDENCE_LOG_FORMAT_VERSION}.`,
    )
  }
}

// ---------------------------------------------------------------------------
// Leaf encoding
// ---------------------------------------------------------------------------

/**
 * The exact byte string a leaf carries:
 *
 *   "pruvz.ai/evidence-log-leaf" 0x00 logVersion 0x00 <canonical JSON of the seal>
 *
 * The document is the seal exactly as transported and stored — the signed
 * envelope plus its signature — so the log witnesses both what was committed
 * to and the signature that committed. A seal whose signature was later
 * swapped hashes to a different leaf.
 */
export function leafInput(seal) {
  if (!isPlainObject(seal) || !isPlainObject(seal.envelope)) {
    fail('LOG_MALFORMED', 'a leaf must be { envelope, signature }')
  }
  if (seal.envelope.version !== LEAF_ENVELOPE_VERSION) {
    fail(
      'LOG_MALFORMED',
      `a leaf carries an envelope of version ${LEAF_ENVELOPE_VERSION}; ` +
        `got ${seal.envelope.version === undefined ? '(none)' : `"${seal.envelope.version}"`}`,
    )
  }
  const signature = decodeBase64Url(seal.signature, 'seal.signature')
  const suiteId = seal.envelope.signer?.suite
  // Object.hasOwn, never `in` or a bare subscript: a suite named like an
  // Object.prototype member ("toString") must be an unknown suite, not a
  // function that fails later with the wrong refusal code.
  const suite = typeof suiteId === 'string' && Object.hasOwn(SUITES, suiteId) ? SUITES[suiteId] : undefined
  if (suite !== undefined && signature.length !== suite.signatureLength) {
    fail(
      'MALFORMED_SIGNATURE',
      `seal.signature is ${signature.length} bytes; suite ${seal.envelope.signer.suite} ` +
        `signatures are exactly ${suite.signatureLength}`,
    )
  }
  const unknown = Object.keys(seal).filter((member) => member !== 'envelope' && member !== 'signature')
  if (unknown.length > 0) {
    fail('LOG_MALFORMED', `a leaf holds exactly envelope and signature; got ${unknown.join(', ')}`)
  }

  const header = [LEAF_DOMAIN_TAG, EVIDENCE_LOG_FORMAT_VERSION, ''].join(HEADER_SEPARATOR)
  return Buffer.concat([Buffer.from(header, 'utf8'), canonicalBytes(seal, 'a leaf')])
}

/** The leaf hash of raw leaf bytes: SHA-256 over a 0x00 prefix then the bytes. */
export function leafHashOf(input) {
  return sha256(Buffer.from([LEAF_HASH_PREFIX]), input)
}

/** The leaf hash of one seal, as 64 lowercase hex digits. */
export function sealLeafHash(seal) {
  return leafHashOf(leafInput(seal)).toString('hex')
}

// ---------------------------------------------------------------------------
// Tree composition (RFC 6962 section 2.1, over precomputed leaf hashes)
// ---------------------------------------------------------------------------

/** The head of the empty tree: SHA-256 of the empty string. */
export function emptyTreeHash() {
  return sha256().toString('hex')
}

const node = (left, right) => sha256(Buffer.from([NODE_HASH_PREFIX]), left, right)

/** The largest power of two strictly less than n (n >= 2). */
const split = (n) => {
  let k = 1
  while (k * 2 < n) {
    k *= 2
  }
  return k
}

const leafBuffers = (leafHashes, field) => {
  if (!Array.isArray(leafHashes)) {
    fail('LOG_MALFORMED', `${field} must be an array of leaf hashes`)
  }
  return leafHashes.map((hash, index) => hashFromHex(hash, `${field}[${index}]`))
}

const head = (hashes, lo, hi) => {
  const n = hi - lo
  if (n === 1) {
    return hashes[lo]
  }
  const k = split(n)
  return node(head(hashes, lo, lo + k), head(hashes, lo + k, hi))
}

/**
 * The tree head over an ordered list of leaf hashes, as hex. The input is the
 * hashes rather than the leaves so that the head of a tree whose old leaves
 * were retention-deleted can still be recomputed: leaf hashes are what the log
 * stores forever, leaf contents are what retention may remove.
 */
export function treeHead(leafHashes) {
  const hashes = leafBuffers(leafHashes, 'leafHashes')
  if (hashes.length === 0) {
    return emptyTreeHash()
  }
  return head(hashes, 0, hashes.length).toString('hex')
}

/** RFC 6962 PATH(m, D[n]): the inclusion path of leaf m in the first n leaves. */
export function inclusionPath(leafIndex, leafHashes) {
  const hashes = leafBuffers(leafHashes, 'leafHashes')
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= hashes.length) {
    fail('LOG_MALFORMED', `leafIndex must be an integer in [0, ${hashes.length})`)
  }
  const path = []
  const walk = (m, lo, hi) => {
    const n = hi - lo
    if (n === 1) {
      return
    }
    const k = split(n)
    if (m < k) {
      walk(m, lo, lo + k)
      path.push(head(hashes, lo + k, hi))
    } else {
      walk(m - k, lo + k, hi)
      path.push(head(hashes, lo, lo + k))
    }
  }
  walk(leafIndex, 0, hashes.length)
  return path.map((hash) => hash.toString('hex'))
}

/** RFC 6962 PROOF(m, D[n]): the consistency proof between sizes m and n, m < n. */
export function consistencyProof(fromSize, leafHashes) {
  const hashes = leafBuffers(leafHashes, 'leafHashes')
  if (!Number.isInteger(fromSize) || fromSize < 1 || fromSize >= hashes.length) {
    fail('LOG_MALFORMED', `fromSize must be an integer in [1, ${hashes.length})`)
  }
  const proof = []
  const subproof = (m, lo, hi, isCompleteSubtree) => {
    const n = hi - lo
    if (m === n) {
      if (!isCompleteSubtree) {
        proof.push(head(hashes, lo, hi))
      }
      return
    }
    const k = split(n)
    if (m <= k) {
      subproof(m, lo, lo + k, isCompleteSubtree)
      proof.push(head(hashes, lo + k, hi))
    } else {
      subproof(m - k, lo + k, hi, false)
      proof.push(head(hashes, lo, lo + k))
    }
  }
  subproof(fromSize, 0, hashes.length, true)
  return proof.map((hash) => hash.toString('hex'))
}

/**
 * Verifies an inclusion proof (RFC 9162 section 2.1.3.2): that the leaf with
 * this hash is the leaf at `leafIndex` of the tree of `treeSize` leaves whose
 * head is `rootHash`. Throws INCLUSION_PROOF_INVALID rather than returning
 * false: a proof that does not verify is a refusal with a reason, never a
 * quiet boolean a caller might forget to check.
 */
export function verifyInclusion({ leafHash, leafIndex, treeSize, path, rootHash } = {}) {
  const leaf = hashFromHex(leafHash, 'leafHash')
  const root = hashFromHex(rootHash, 'rootHash')
  if (!Number.isInteger(leafIndex) || leafIndex < 0) {
    fail('LOG_MALFORMED', 'leafIndex must be a non-negative integer')
  }
  if (!Number.isInteger(treeSize) || treeSize < 1) {
    fail('LOG_MALFORMED', 'treeSize must be a positive integer')
  }
  if (!Array.isArray(path)) {
    fail('LOG_MALFORMED', 'path must be an array of node hashes')
  }
  const nodes = path.map((hash, index) => hashFromHex(hash, `path[${index}]`))

  if (leafIndex >= treeSize) {
    fail(
      'INCLUSION_PROOF_INVALID',
      `leaf index ${leafIndex} does not exist in a tree of ${treeSize} leaves`,
    )
  }

  let fn = leafIndex
  let sn = treeSize - 1
  let r = leaf
  for (const p of nodes) {
    if (sn === 0) {
      fail('INCLUSION_PROOF_INVALID', 'the path is longer than the tree is deep')
    }
    if (fn % 2 === 1 || fn === sn) {
      r = node(p, r)
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2)
          sn = Math.floor(sn / 2)
        }
      }
    } else {
      r = node(r, p)
    }
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }
  if (sn !== 0) {
    fail('INCLUSION_PROOF_INVALID', 'the path is shorter than the tree is deep')
  }
  if (!r.equals(root)) {
    fail(
      'INCLUSION_PROOF_INVALID',
      'the path does not lead this leaf to this root — the leaf is not at this ' +
        'position of this tree, or the record it encodes was altered',
    )
  }
}

/**
 * Verifies a consistency proof (RFC 9162 section 2.1.4.2): that the tree of
 * `toSize` leaves with head `toRootHash` is an append-only extension of the
 * tree of `fromSize` leaves with head `fromRootHash`. This is the check that
 * makes deletion, insertion and reordering of already-checkpointed history
 * detectable: any of them changes what the first `fromSize` leaves hash to,
 * and no proof can then connect the two heads.
 */
export function verifyConsistency({ fromSize, fromRootHash, toSize, toRootHash, proof } = {}) {
  const fromRoot = hashFromHex(fromRootHash, 'fromRootHash')
  const toRoot = hashFromHex(toRootHash, 'toRootHash')
  if (!Number.isInteger(fromSize) || fromSize < 1) {
    fail('LOG_MALFORMED', 'fromSize must be a positive integer')
  }
  if (!Number.isInteger(toSize) || toSize < 1) {
    fail('LOG_MALFORMED', 'toSize must be a positive integer')
  }
  if (!Array.isArray(proof)) {
    fail('LOG_MALFORMED', 'proof must be an array of node hashes')
  }
  let nodes = proof.map((hash, index) => hashFromHex(hash, `proof[${index}]`))

  if (fromSize > toSize) {
    fail(
      'CONSISTENCY_PROOF_INVALID',
      `a tree of ${toSize} leaves cannot extend a tree of ${fromSize}`,
    )
  }
  if (fromSize === toSize) {
    if (nodes.length !== 0) {
      fail('CONSISTENCY_PROOF_INVALID', 'equal sizes take an empty proof')
    }
    if (!fromRoot.equals(toRoot)) {
      fail(
        'CONSISTENCY_PROOF_INVALID',
        'two heads at one size disagree — the tree was altered in place',
      )
    }
    return
  }

  // If fromSize is an exact power of two, the old head is itself the first
  // component of the computation and the proof does not repeat it.
  if ((fromSize & (fromSize - 1)) === 0) {
    nodes = [fromRoot, ...nodes]
  }
  if (nodes.length === 0) {
    fail('CONSISTENCY_PROOF_INVALID', 'the proof is empty')
  }

  let fn = fromSize - 1
  let sn = toSize - 1
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }

  let [first, ...rest] = nodes
  let fr = first
  let sr = first
  for (const c of rest) {
    if (sn === 0) {
      fail('CONSISTENCY_PROOF_INVALID', 'the proof is longer than the new tree is deep')
    }
    if (fn % 2 === 1 || fn === sn) {
      fr = node(c, fr)
      sr = node(c, sr)
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2)
          sn = Math.floor(sn / 2)
        }
      }
    } else {
      sr = node(sr, c)
    }
    fn = Math.floor(fn / 2)
    sn = Math.floor(sn / 2)
  }

  if (sn !== 0) {
    fail('CONSISTENCY_PROOF_INVALID', 'the proof is shorter than the new tree is deep')
  }
  if (!fr.equals(fromRoot)) {
    fail(
      'CONSISTENCY_PROOF_INVALID',
      'the proof does not reproduce the old head — the checkpointed history was altered',
    )
  }
  if (!sr.equals(toRoot)) {
    fail('CONSISTENCY_PROOF_INVALID', 'the proof does not reproduce the new head')
  }
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

const CHECKPOINT_MEMBERS = [
  'assuranceProfile',
  'checkpointSequence',
  'issuedAt',
  'origin',
  'rootHash',
  'signer',
  'treeSize',
  'version',
]

const SIGNER_MEMBERS = ['keyId', 'provider', 'suite']

/**
 * Validates a checkpoint document — the signed statement "the log named
 * `origin` had `treeSize` leaves and head `rootHash` when checkpoint number
 * `checkpointSequence` was issued".
 *
 * The member set is closed and everything security-relevant is inside the
 * signature, exactly like the envelope: a transported checkpoint carries no
 * unsigned copy of anything for a verifier to read, so tampering changes the
 * signed bytes and fails verification rather than changing what the signature
 * is understood to mean. `issuedAt` is self-asserted, like `committedAt`.
 */
export function validateCheckpointDocument(document) {
  if (!isPlainObject(document)) {
    fail('LOG_MALFORMED', 'a checkpoint must be an object')
  }
  requireSupported(document.version)

  const unknown = Object.keys(document).filter((member) => !CHECKPOINT_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail('LOG_MALFORMED', `a checkpoint carries ${unknown.join(', ')}; the member set is closed`)
  }
  const missing = CHECKPOINT_MEMBERS.filter((member) => !(member in document))
  if (missing.length > 0) {
    fail('LOG_MALFORMED', `a checkpoint is missing ${missing.join(', ')}`)
  }

  if (!ASSURANCE_PROFILES.includes(document.assuranceProfile)) {
    fail(
      'LOG_MALFORMED',
      `assuranceProfile must be one of ${ASSURANCE_PROFILES.join(', ')}`,
    )
  }
  safePositiveInteger(document.checkpointSequence, 'checkpointSequence')
  safePositiveInteger(document.treeSize, 'treeSize')
  boundText(document.origin, 'origin')
  if (typeof document.rootHash !== 'string' || !ROOT_HASH.test(document.rootHash)) {
    fail('LOG_MALFORMED', 'rootHash must be "sha256:" then 64 lowercase hex digits')
  }
  let issuedAtCanonical = null
  try {
    issuedAtCanonical = typeof document.issuedAt === 'string' ? canonicalTimestamp(document.issuedAt) : null
  } catch {
    // fall through to the refusal below — the canonical layer's own refusal
    // vocabulary never leaks out of this format's.
  }
  if (issuedAtCanonical !== document.issuedAt) {
    fail('LOG_MALFORMED', 'issuedAt must be a canonical UTC timestamp')
  }

  if (!isPlainObject(document.signer)) {
    fail('LOG_MALFORMED', 'signer must be an object')
  }
  const signerUnknown = Object.keys(document.signer).filter(
    (member) => !SIGNER_MEMBERS.includes(member),
  )
  if (signerUnknown.length > 0) {
    fail('LOG_MALFORMED', `signer carries ${signerUnknown.join(', ')}; it holds exactly keyId, provider, suite`)
  }
  boundText(document.signer.keyId, 'signer.keyId')
  boundText(document.signer.provider, 'signer.provider')
  if (typeof document.signer.suite !== 'string' || !Object.hasOwn(SUITES, document.signer.suite)) {
    fail('LOG_MALFORMED', `signer.suite "${document.signer.suite}" is not a suite this contract defines`)
  }

  return document
}

/**
 * The exact byte string a checkpoint signature covers:
 *
 *   "pruvz.ai/log-checkpoint" 0x00 version 0x00 <canonical JSON of the checkpoint>
 *
 * The version appears once, inside the signed document, and the header is
 * derived from it — a derivation, never a second unsigned copy.
 */
export function checkpointSigningInput(document) {
  validateCheckpointDocument(document)
  const header = [CHECKPOINT_DOMAIN_TAG, document.version, ''].join(HEADER_SEPARATOR)
  return Buffer.concat([Buffer.from(header, 'utf8'), canonicalBytes(document, 'a checkpoint')])
}

/**
 * Verifies a signed checkpoint against a public key the caller resolved
 * independently — normally from the published trust registry, by the
 * checkpoint's own `signer.keyId`, with the registry deciding whether that key
 * was a trustworthy evidence key at the time. Key-trust resolution is the
 * registry layer's question (docs/TRUST-REGISTRY.md) and is deliberately not
 * repeated here.
 */
export function verifyCheckpoint({ checkpoint, signature, jwk } = {}) {
  validateCheckpointDocument(checkpoint)
  const suite = SUITES[checkpoint.signer.suite]
  const signatureBytes = decodeBase64Url(signature, 'signature')
  if (signatureBytes.length !== suite.signatureLength) {
    fail(
      'MALFORMED_SIGNATURE',
      `signature is ${signatureBytes.length} bytes; suite ${checkpoint.signer.suite} ` +
        `signatures are exactly ${suite.signatureLength}`,
    )
  }
  if (!isPlainObject(jwk)) {
    fail('INVALID_PUBLIC_KEY', 'jwk must be a public JSON Web Key object')
  }

  let key
  try {
    key = createPublicKey({ key: jwk, format: 'jwk' })
  } catch {
    fail('INVALID_PUBLIC_KEY', 'jwk is not a valid public key')
  }

  const verifies = verifyEcdsa(
    suite.hash,
    checkpointSigningInput(checkpoint),
    { key, dsaEncoding: 'ieee-p1363' },
    signatureBytes,
  )
  if (!verifies) {
    fail(
      'CHECKPOINT_SIGNATURE_INVALID',
      'the signature over this checkpoint does not verify under this key',
    )
  }
}

/**
 * Decides whether a verifier that has already accepted one checkpoint may
 * accept another, and returns the new accepted state. This is where fork,
 * rollback and stale presentation become refusals rather than surprises — and
 * only for a verifier that KEEPS its accepted state, exactly like the trust
 * registry's chain rules: the history the verifier already holds is what makes
 * a contradictory checkpoint detectable.
 *
 * The candidate must already have been validated and signature-verified
 * (`verifyCheckpoint`) and its key trust resolved through the registry; this
 * function orders trees, it does not check signatures.
 *
 * Checkpoint sequences may have gaps from the verifier's point of view — a
 * verifier need not witness every checkpoint a log issues — which is why
 * consecutive ACCEPTED checkpoints must be connected by a consistency proof
 * rather than by sequence adjacency.
 */
export function acceptCheckpoint({ accepted = null, candidate, consistencyProof: proof } = {}) {
  validateCheckpointDocument(candidate)
  const state = {
    checkpointSequence: candidate.checkpointSequence,
    origin: candidate.origin,
    rootHash: candidate.rootHash,
    treeSize: candidate.treeSize,
  }

  if (accepted === null) {
    // First acceptance: nothing to compare against. What anchors THIS trust —
    // out-of-band pinning, external witnessing — is the registry's bootstrap
    // story and PRUVZ-96's anchoring story, honestly not this function's.
    return state
  }
  if (!isPlainObject(accepted)) {
    fail('LOG_MALFORMED', 'accepted must be the state a previous acceptance returned')
  }
  // The held state is checked with the same rules the candidate met, so a
  // caller that hands back something other than a previous acceptance gets
  // this format's refusal rather than a runtime error from the comparison.
  boundText(accepted.origin, 'accepted.origin')
  safePositiveInteger(accepted.checkpointSequence, 'accepted.checkpointSequence')
  safePositiveInteger(accepted.treeSize, 'accepted.treeSize')
  if (typeof accepted.rootHash !== 'string' || !ROOT_HASH.test(accepted.rootHash)) {
    fail('LOG_MALFORMED', 'accepted.rootHash must be "sha256:" then 64 lowercase hex digits')
  }

  if (candidate.origin !== accepted.origin) {
    fail(
      'CHECKPOINT_ORIGIN_MISMATCH',
      `this checkpoint is from log "${candidate.origin}", not "${accepted.origin}" — ` +
        'two different logs cannot vouch for each other',
    )
  }

  if (candidate.checkpointSequence < accepted.checkpointSequence) {
    fail(
      'CHECKPOINT_STALE',
      `checkpoint ${candidate.checkpointSequence} is older than the already accepted ` +
        `${accepted.checkpointSequence} and cannot be presented as current`,
    )
  }

  if (candidate.checkpointSequence === accepted.checkpointSequence) {
    if (candidate.treeSize === accepted.treeSize && candidate.rootHash === accepted.rootHash) {
      return { ...state } // the same checkpoint, seen again
    }
    fail(
      'CHECKPOINT_FORK',
      `two checkpoints numbered ${candidate.checkpointSequence} disagree — the log ` +
        'presented two histories. Neither is "corrupt"; only held history reveals this.',
    )
  }

  if (candidate.treeSize < accepted.treeSize) {
    fail(
      'CHECKPOINT_ROLLBACK',
      `checkpoint ${candidate.checkpointSequence} covers ${candidate.treeSize} leaves but ` +
        `${accepted.checkpointSequence} already covered ${accepted.treeSize} — the log shrank`,
    )
  }

  if (candidate.treeSize === accepted.treeSize) {
    if (candidate.rootHash !== accepted.rootHash) {
      fail(
        'CHECKPOINT_FORK',
        'a later checkpoint at the same tree size names a different head — the tree was ' +
          'altered in place',
      )
    }
    return state
  }

  verifyConsistency({
    fromSize: accepted.treeSize,
    fromRootHash: accepted.rootHash.slice('sha256:'.length),
    toSize: candidate.treeSize,
    toRootHash: candidate.rootHash.slice('sha256:'.length),
    proof: proof ?? [],
  })
  return state
}
