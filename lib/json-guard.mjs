// Duplicate-member detection over RAW JSON text (PRUVZ-97).
//
// RFC 8259 leaves duplicate member names undefined, and real parsers disagree:
// most keep the last occurrence, some the first. One byte string that parses
// as two different documents is exactly the ambiguity an adversarial export
// exploits — a reviewer reads the first occurrence while a last-wins parser
// commits to the second. At a trust boundary that is not a nuance, it is
// unusable input, and every conformant verifier refuses it before parsing
// (docs/VERIFIER.md §2, conformance/v1 case `duplicate-member-refused`).
//
// This is a structural scan, not a parser: it tokenizes just enough JSON to
// track object member names per nesting level. It never evaluates values and
// has no lenient mode.

/** Thrown when one byte string could parse as two different documents. */
export class DuplicateMemberError extends Error {
  constructor(message) {
    super(message)
    this.name = 'DuplicateMemberError'
  }
}

/**
 * Scans raw JSON text and throws DuplicateMemberError when any object carries
 * the same member name twice. Malformed JSON is not this guard's business —
 * the caller's parser will refuse it — but the scan is defensive enough not
 * to misreport on text the parser would reject anyway.
 */
export function assertUniqueMembers(text) {
  const stack = [] // one Set per open object; null per open array
  let index = 0
  let expectName = false

  // Escapes are DECODED, because member equality is decided on decoded values:
  // `"a"` and `"a"` are one name to every JSON parser, and comparing raw
  // spellings would let a duplicate hide behind an escape (PRUVZ-97 review
  // finding). Decoding is per UTF-16 code unit — a surrogate pair written as
  // two \uXXXX escapes equals the literal character, exactly as JSON.parse
  // reads it. An invalid escape is kept raw: the parser refuses the text.
  const SIMPLE_ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
  const readString = () => {
    // index is at the opening quote
    let out = ''
    index += 1
    while (index < text.length) {
      const char = text[index]
      if (char === '\\') {
        const escape = text[index + 1]
        if (escape === 'u') {
          const hex = text.slice(index + 2, index + 6)
          if (/^[0-9a-fA-F]{4}$/.test(hex)) {
            out += String.fromCharCode(Number.parseInt(hex, 16))
            index += 6
            continue
          }
        } else if (escape in SIMPLE_ESCAPES) {
          out += SIMPLE_ESCAPES[escape]
          index += 2
          continue
        }
        out += text.slice(index, index + 2)
        index += 2
        continue
      }
      if (char === '"') {
        index += 1
        return out
      }
      out += char
      index += 1
    }
    return out // unterminated: the parser will refuse the text itself
  }

  while (index < text.length) {
    const char = text[index]
    if (char === '{') {
      stack.push(new Set())
      expectName = true
      index += 1
    } else if (char === '[') {
      stack.push(null)
      expectName = false
      index += 1
    } else if (char === '}' || char === ']') {
      stack.pop()
      expectName = false
      index += 1
    } else if (char === '"') {
      const start = index
      const value = readString()
      const scope = stack[stack.length - 1]
      if (expectName && scope instanceof Set) {
        // A name only when followed by a colon — defensive: in valid JSON the
        // expectName flag already guarantees it.
        let lookahead = index
        while (lookahead < text.length && /\s/.test(text[lookahead])) lookahead += 1
        if (text[lookahead] === ':') {
          if (scope.has(value)) {
            throw new DuplicateMemberError(
              `duplicate member name ${JSON.stringify(value)} at offset ${start}: one byte ` +
                'string that parses as two different documents is unusable input',
            )
          }
          scope.add(value)
          expectName = false
        }
      }
    } else if (char === ',') {
      expectName = stack[stack.length - 1] instanceof Set
      index += 1
    } else {
      index += 1
    }
  }
}
