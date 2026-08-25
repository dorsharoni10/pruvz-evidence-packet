// Reference implementation of the Pruvz Canonical Commitment, format version 1.
//
// A commitment is the answer to one question: are these the exact logical
// values Pruvz committed to? It is not a claim that those values are factually
// correct — cryptography preserves evidence, it does not make evidence true.
//
// Two layers, specified in docs/COMMITMENT.md:
//   1. A canonical value model. Only objects, arrays, strings, booleans, null
//      and SAFE INTEGERS may be committed. Every precision-sensitive value —
//      money above all — is carried as a normalized string, so no runtime ever
//      re-reads a committed number through IEEE-754 double semantics.
//   2. RFC 8785 (JCS) serialization of that model, prefixed with a
//      domain-separation header naming the commitment version and the kind of
//      record, then hashed with a named digest suite.
//
// Everything here fails closed. An unknown kind, an unknown digest suite, a
// non-integer number, a money value without its exact representation, a
// non-UTC timestamp or a lone surrogate is an error — never a rounded,
// coerced or silently accepted commitment.
//
// This file is the second-runtime reference for the .NET implementation in
// pruvz-core. Neither is authoritative on its own: both must reproduce the
// published golden vectors in commitment/v1/golden-vectors.json byte for byte.
import { createHash } from 'node:crypto'

/** The commitment format this implementation speaks. */
export const COMMITMENT_VERSION = '1'

/** Digest suites this commitment version defines, by their suite id. */
export const DIGEST_SUITES = ['sha-256']

/** The kinds of record a commitment may cover. Closed by design. */
export const COMMITMENT_KINDS = ['evidence-item', 'evidence-packet']

/** Domain-separation tag: commitments of different kinds can never collide. */
const DOMAIN_TAG = 'pruvz.ai/commitment'

/**
 * The header field separator: a NUL byte, which cannot occur in the tag, the
 * version or a kind — so no combination of them can be re-read as another.
 */
const HEADER_SEPARATOR = '\u0000'

const MAX_SAFE_INTEGER = 9007199254740991

/**
 * Every reason a commitment can be refused. The codes are part of the
 * specification: a golden vector names the code it expects, so two runtimes
 * must refuse the same input for the same reason — not merely both throw.
 */
export const REFUSAL_CODES = [
  'INTEGER_OUT_OF_RANGE',
  'INVALID_CURRENCY',
  'INVALID_DOCUMENT',
  'INVALID_MONEY',
  'LONE_SURROGATE',
  'MISSING_BINDING',
  'MISSING_FIELD',
  'MONEY_WITHOUT_EXACT_AMOUNT',
  'NEGATIVE_ZERO',
  'NON_CANONICAL_DECIMAL',
  'NON_INTEGER_NUMBER',
  'NON_UTC_TIMESTAMP',
  'UNKNOWN_COMMITMENT_VERSION',
  'UNKNOWN_DIGEST_SUITE',
  'UNKNOWN_KIND',
  'UNSUPPORTED_VALUE',
]

/** Thrown for every refusal. There is no lenient mode. */
export class CommitmentError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'CommitmentError'
    this.code = code
  }
}

const fail = (code, message) => {
  throw new CommitmentError(code, message)
}

const CONTROL_ESCAPES = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
}

/**
 * Serializes one string per RFC 8785 section 3.2.2.2: the two mandatory
 * escapes, the five short forms, \u00xx for the remaining C0 controls, and
 * every other code point literally. A lone surrogate is not text and cannot be
 * encoded as UTF-8, so it is refused rather than replaced with U+FFFD.
 */
const serializeString = (value, path) => {
  let out = '"'
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index]
    const code = value.charCodeAt(index)

    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail('LONE_SURROGATE', `${path}: unpaired high surrogate at index ${index}`)
      }
      out += char + value[index + 1]
      index += 1
      continue
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      fail('LONE_SURROGATE', `${path}: unpaired low surrogate at index ${index}`)
    }

    if (CONTROL_ESCAPES[char] !== undefined) {
      out += CONTROL_ESCAPES[char]
    } else if (code < 0x20) {
      out += `\\u${code.toString(16).padStart(4, '0')}`
    } else {
      out += char
    }
  }
  return `${out}"`
}

const serializeValue = (value, path) => {
  if (value === null) {
    return 'null'
  }
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false'
  }
  if (typeof value === 'string') {
    return serializeString(value, path)
  }
  if (typeof value === 'number') {
    // The whole point of the canonical value model: a committed number is an
    // exact integer or it is not committed at all. 25.00 does not quietly
    // become 25 here — it never reaches this function, because money is
    // carried as its exact decimal string.
    //
    // What is committed is the value, never its spelling: a JSON parser has
    // already discarded whether an integer was written 5, 5.0 or 5e0, and all
    // three denote the same value and therefore the same commitment. A second
    // runtime that can still see the original text must judge the value too,
    // or it would refuse documents this one commits (golden vector
    // "integer-spellings").
    if (!Number.isInteger(value) || Object.is(value, -0)) {
      fail(
        'NON_INTEGER_NUMBER',
        `${path}: only integers may be committed (got ${value}); ` +
          'precision-sensitive values are committed as canonical decimal strings',
      )
    }
    if (Math.abs(value) > MAX_SAFE_INTEGER) {
      fail('INTEGER_OUT_OF_RANGE', `${path}: integer ${value} is outside the safe integer range`)
    }
    return String(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => serializeValue(item, `${path}/${index}`)).join(',')}]`
  }
  if (typeof value === 'object') {
    // A Date, a Map or a class instance has no own enumerable members, so it
    // would serialize as {} and commit nothing at all. Only a plain object —
    // what a JSON parser produces — carries its data in its own members.
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) {
      fail(
        'UNSUPPORTED_VALUE',
        `${path}: only a plain object can be committed (got ${value.constructor?.name ?? 'a non-plain object'}); ` +
          'anything else would commit as {} and silently lose its content',
      )
    }

    // JCS orders members by UTF-16 code unit, which is exactly what the
    // default string sort compares.
    const keys = Object.keys(value).sort()
    const members = keys.map((key) => {
      const member = value[key]
      if (member === undefined) {
        fail('UNSUPPORTED_VALUE', `${path}/${key}: undefined is not a JSON value`)
      }
      return `${serializeString(key, `${path}/${key}`)}:${serializeValue(member, `${path}/${key}`)}`
    })
    return `{${members.join(',')}}`
  }

  return fail('UNSUPPORTED_VALUE', `${path}: ${typeof value} cannot be committed`)
}

/**
 * Serializes a commitment document to its canonical UTF-8 bytes (RFC 8785 over
 * the canonical value model). This is the document alone — commitmentInput()
 * adds the domain-separation header that is actually hashed.
 */
export function canonicalize(document) {
  return Buffer.from(serializeValue(document, '$'), 'utf8')
}

/**
 * The exact byte string a commitment hashes:
 *
 *   "pruvz.ai/commitment" 0x00 version 0x00 kind 0x00 <canonical JSON>
 *
 * The header is what keeps an evidence item's commitment from ever being read
 * as a packet's, or a version-1 commitment as a future version's.
 */
export function commitmentInput(kind, document) {
  if (!COMMITMENT_KINDS.includes(kind)) {
    fail(
      'UNKNOWN_KIND',
      `Unknown commitment kind "${kind}". Known kinds: ${COMMITMENT_KINDS.join(', ')}.`,
    )
  }
  const header = [DOMAIN_TAG, COMMITMENT_VERSION, kind, ''].join(HEADER_SEPARATOR)
  return Buffer.concat([Buffer.from(header, 'utf8'), canonicalize(document)])
}

/**
 * The commitment digest of a document: "sha256:" followed by 64 lowercase hex
 * digits. The suite id is explicit and closed so that a future suite is a
 * decision, never a default.
 */
export function commitmentDigest(kind, document, suite = DIGEST_SUITES[0]) {
  if (!DIGEST_SUITES.includes(suite)) {
    fail(
      'UNKNOWN_DIGEST_SUITE',
      `Unknown digest suite "${suite}". Known suites: ${DIGEST_SUITES.join(', ')}.`,
    )
  }
  const digest = createHash('sha256').update(commitmentInput(kind, document)).digest('hex')
  return `sha256:${digest}`
}

/**
 * Refuses a commitment this implementation cannot speak, before any byte of it
 * is trusted. Anything that reads a commitment version or digest suite from a
 * document — a future signed envelope, a verifier — calls this first: an
 * unrecognized version must never be silently treated as version 1, whose
 * rules it may not follow.
 */
export function requireSupported(commitmentVersion, digestSuite = DIGEST_SUITES[0]) {
  if (commitmentVersion !== COMMITMENT_VERSION) {
    fail(
      'UNKNOWN_COMMITMENT_VERSION',
      `Unknown commitment version "${commitmentVersion}". This implementation speaks ` +
        `version ${COMMITMENT_VERSION}.`,
    )
  }
  if (!DIGEST_SUITES.includes(digestSuite)) {
    fail(
      'UNKNOWN_DIGEST_SUITE',
      `Unknown digest suite "${digestSuite}". Known suites: ${DIGEST_SUITES.join(', ')}.`,
    )
  }
}

const EXACT_DECIMAL = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/

/**
 * Normalizes an exact decimal string to its canonical spelling: no exponent,
 * no plus sign, no leading zeros, no trailing zeros in the fraction, one
 * spelling of zero. "25.00" becomes "25"; "0.500" becomes "0.5".
 *
 * Input must already be exact decimal text. A number is never accepted here —
 * by the time a value is a JavaScript number its exactness is already gone.
 */
export function canonicalDecimal(text) {
  if (typeof text !== 'string') {
    fail('NON_CANONICAL_DECIMAL', `An exact decimal must be a string, not ${typeof text}`)
  }
  if (!EXACT_DECIMAL.test(text)) {
    fail(
      'NON_CANONICAL_DECIMAL',
      `"${text}" is not an exact decimal (no exponent, no plus sign, no leading zeros)`,
    )
  }

  const [integer, rawFraction = ''] = text.split('.')
  const fraction = rawFraction.replace(/0+$/, '')

  if (integer === '-0' && fraction === '') {
    fail('NEGATIVE_ZERO', 'Negative zero has no canonical decimal form; write 0')
  }

  return fraction === '' ? integer : `${integer}.${fraction}`
}

const UTC_TIMESTAMP = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$/

/**
 * Normalizes a UTC timestamp to one spelling per instant: RFC 3339 with the Z
 * designator, the fraction present only when it is non-zero and never carrying
 * trailing zeros. A local-offset form is refused rather than converted — the
 * contract exports UTC, and silently converting would hide a producer defect.
 *
 * The rule is deliberately lexical: it fixes the grammar and the spelling, not
 * the calendar. Whether an instant exists is the packet schema's business
 * (date-time format); a commitment must reproduce what the producer wrote, and
 * a runtime that reinterpreted a date here would commit something else.
 */
export function canonicalTimestamp(text) {
  if (typeof text !== 'string') {
    fail('NON_UTC_TIMESTAMP', `A UTC timestamp must be a string, not ${typeof text}`)
  }
  const match = UTC_TIMESTAMP.exec(text)
  if (match === null) {
    fail(
      'NON_UTC_TIMESTAMP',
      `"${text}" is not a UTC timestamp of the form YYYY-MM-DDTHH:MM:SS[.fraction]Z`,
    )
  }

  const fraction = (match[2] ?? '').replace(/0+$/, '')
  return fraction === '' ? `${match[1]}Z` : `${match[1]}.${fraction}Z`
}

/** The complete member set of a money value. A money value carries no more. */
const MONEY_MEMBERS = ['amount', 'amountExact', 'currency']

/**
 * Whether a value is a money value. One definition, shared by the committer
 * and by the packet validator — two predicates would eventually disagree about
 * what an amount is.
 *
 * A `currency` member is what identifies one: the test must also recognize a
 * pre-1.4.0 money value, which carries no exact amount, so that it is refused
 * as un-committable rather than committed as an ordinary object.
 */
export const isMoney = (value) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  typeof value.currency === 'string'

/**
 * The committed form of a money value: its exact decimal string and its
 * currency, and nothing else. The JSON number is deliberately dropped — it is
 * a display convenience, not the value, and committing it would make the
 * commitment depend on how a runtime happens to print a double.
 *
 * Because members are dropped, the member set is closed: an object carrying
 * anything beyond a money value's three members is refused rather than
 * committed with the extra member silently missing.
 */
export function canonicalMoney(money, path = '$') {
  if (!isMoney(money)) {
    fail('INVALID_MONEY', `${path}: not a money value`)
  }
  if (typeof money.amountExact !== 'string') {
    fail(
      'MONEY_WITHOUT_EXACT_AMOUNT',
      `${path}: money must carry amountExact (packet format 1.4.0 or later); ` +
        'an amount that exists only as a JSON number cannot be committed exactly',
    )
  }

  const unknown = Object.keys(money).filter((member) => !MONEY_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail(
      'INVALID_MONEY',
      `${path}: a money value carries only ${MONEY_MEMBERS.join(', ')}; refusing to commit one ` +
        `that also carries ${unknown.join(', ')} — the extra member would be dropped in silence`,
    )
  }

  if (!/^[A-Z]{3}$/.test(money.currency)) {
    fail('INVALID_CURRENCY', `${path}: currency must be a three-letter uppercase ISO 4217 code`)
  }

  return { amount: canonicalDecimal(money.amountExact), currency: money.currency }
}

/**
 * Normalizes an exported packet into the canonical value model: money values
 * become their exact form, every *AtUtc member becomes a canonical UTC
 * timestamp, and everything else keeps its structure. A non-integer number
 * outside a money value is a refusal, not a rounding.
 */
const normalizePacketValue = (value, path, key) => {
  if (isMoney(value)) {
    return canonicalMoney(value, path)
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => normalizePacketValue(item, `${path}/${index}`, null))
  }
  if (value !== null && typeof value === 'object') {
    const out = {}
    for (const member of Object.keys(value)) {
      out[member] = normalizePacketValue(value[member], `${path}/${member}`, member)
    }
    return out
  }
  if (typeof value === 'string' && key !== null && key.endsWith('AtUtc')) {
    return canonicalTimestamp(value)
  }
  return value
}

/**
 * The commitment document for one exported Evidence Packet: the trust-domain
 * binding the packet itself does not carry, and the normalized packet.
 *
 * A verifier that checks this digest must ALSO check the packet's own
 * consistency (validatePacket): the commitment binds the exact amount, so a
 * packet whose display number disagrees with its exact amount is a defective
 * packet even though its commitment still verifies.
 */
export function evidencePacketDocument({ tenantId, packet }) {
  if (typeof tenantId !== 'string' || tenantId.length === 0) {
    fail(
      'MISSING_BINDING',
      'A commitment must bind a tenantId: evidence is only meaningful inside its trust domain',
    )
  }
  if (packet === null || typeof packet !== 'object' || Array.isArray(packet)) {
    fail('INVALID_DOCUMENT', 'packet must be the parsed Evidence Packet document')
  }
  if (typeof packet.action?.actionId !== 'string') {
    fail('MISSING_BINDING', 'packet.action.actionId is required to bind the commitment')
  }

  return {
    binding: { actionId: packet.action.actionId, tenantId },
    content: normalizePacketValue(packet, '$', null),
  }
}

/** Every field of an evidence item that the commitment covers. */
const EVIDENCE_ITEM_FIELDS = [
  'clientOperationId',
  'evidenceId',
  'occurredAtUtc',
  'payloadMetadata',
  'recordedAtUtc',
  'runId',
  'schemaVersion',
  'sequence',
  'source',
  'sourceReference',
  'summary',
  'trustLevel',
  'type',
]

/**
 * The commitment document for one evidence item — the internal append-only
 * record, not the public timeline view, because the item is the unit that is
 * written once and never mutated. Every covered field must be present: an
 * absent field would silently shrink what the commitment protects.
 */
export function evidenceItemDocument({ tenantId, actionId, item }) {
  if (typeof tenantId !== 'string' || tenantId.length === 0) {
    fail(
      'MISSING_BINDING',
      'A commitment must bind a tenantId: evidence is only meaningful inside its trust domain',
    )
  }
  if (typeof actionId !== 'string' || actionId.length === 0) {
    fail('MISSING_BINDING', 'A commitment must bind an actionId')
  }
  if (item === null || typeof item !== 'object' || Array.isArray(item)) {
    fail('INVALID_DOCUMENT', 'item must be the evidence item record')
  }

  const content = {}
  for (const field of EVIDENCE_ITEM_FIELDS) {
    if (!(field in item)) {
      fail(
        'MISSING_FIELD',
        `item.${field} is required: the commitment covers every field of the item`,
      )
    }
    const value = item[field]
    content[field] = field.endsWith('AtUtc') ? canonicalTimestamp(value) : value
  }

  return { binding: { actionId, tenantId }, content }
}
