# Canonical commitment, version 1

A **commitment** is a digest over one deterministic byte string derived from a
record. Two runtimes that follow this specification produce the same bytes, and
therefore the same digest, for the same logical record.

That is all a commitment does. It answers *are these the exact logical values
Pruvz committed to?* — never *is what Pruvz recorded true?* Capture fidelity is
established by independent system-of-record read-back inside the product;
post-capture integrity is established here. The two are separate assurance
dimensions and neither substitutes for the other.

This release publishes the **format and its golden vectors only**. Nothing in
the packet is signed yet: no signature envelope, no key material, no
append-only log, no external anchor. Those are later, separately released
capabilities. A packet of format `1.4.0` carries the exact values a commitment
needs; it does not carry a commitment.

- Reference implementation: [`lib/canonical.mjs`](../lib/canonical.mjs)
- Golden vectors: [`commitment/v1/golden-vectors.json`](../commitment/v1/golden-vectors.json)

## 1. The canonical value model

A **commitment document** is a JSON value restricted to:

| Type | Rule |
|---|---|
| object | Member names unique; any Unicode string |
| array | Order is data and is never rearranged |
| string | Any well-formed Unicode text; lone surrogates are refused |
| number | **Integers only**, within ±(2⁵³−1) |
| boolean, null | As-is; `null` is a committed value, not an omission |

Numbers are the whole point of the restriction. An IEEE-754 double cannot hold
every decimal value exactly, and two runtimes need not print the same double
the same way, so a precision-sensitive value carried as a JSON number is not
committable. Every such value — money above all — is carried as a **normalized
string** instead (§3). A non-integer number anywhere in a commitment document
is refused, never rounded.

What is committed is a number's **value, never its spelling**. `5`, `5.0` and
`5e0` denote one integer and produce one commitment; `5e2` commits as `500`.
This is not a convenience: a runtime whose JSON parser keeps only the value
cannot tell the three apart, so a runtime that can see the original text must
still judge the value, or the two would disagree about the same logical record.
An implementation that refused `5.0` would be refusing a document another
conforming implementation commits. `-0` is refused rather than committed as
`0`, because zero has one spelling.

`null` and *absent* are different commitments. A field that may be empty is
committed as `null` rather than dropped, so a record cannot be silently shrunk.

## 2. Serialization

The document is serialized per **RFC 8785 (JSON Canonicalization Scheme)**,
restricted to the value model above:

- Object members are ordered by **UTF-16 code unit** of the member name, at
  every level. Uppercase therefore sorts before lowercase.
- Strings escape `"` and `\`; use `\b`, `\t`, `\n`, `\f`, `\r` for those five
  controls; use `\u00xx` (lowercase hex) for the remaining C0 controls; and
  emit every other code point literally.
- No insignificant whitespace. Output is UTF-8.
- Integers are written without a plus sign, leading zeros or exponent.

Because only integers are admitted, the ECMAScript number formatting of RFC
8785 §3.2.2.3 is never reached — the one part of JCS whose result depends on
floating-point behaviour is out of scope by construction.

## 3. Normalized value types

### Money

A money value is committed as its exact decimal string and its currency:

```json
{ "amount": "42.5", "currency": "USD" }
```

The **canonical decimal** form gives one value exactly one spelling: no
exponent, no plus sign, no leading zeros (zero is a bare `0`), and no trailing
zeros in the fraction. `25.00` normalizes to `25`; `0.500` to `0.5`; `-0` is
refused, because zero has one spelling.

A money value's member set is **closed**: `amount`, `amountExact`, `currency`
and nothing else. Only the exact amount and the currency are committed, so an
object carrying a fourth member is refused rather than committed with that
member silently missing from the digest.

In an exported packet a money value states its amount twice — `amount`, the
JSON number consumers display, and `amountExact`, the canonical decimal string
(packet format `1.4.0`). **The commitment binds `amountExact` and ignores the
number entirely.**

The number is the nearest double to the exact amount — that is all a JSON
number can ever be. Above double precision it is approximate by construction,
and below it no JSON number can witness the exact value at all. That is the
reason the commitment binds the string, and the reason the packet's own
consistency rule compares the two numerically rather than by their printed
forms.

That leaves one consequence a verifier must act on: a packet whose display
number disagrees with its exact amount still satisfies its commitment while
showing a human reader a different figure. Checking a commitment is therefore
never sufficient on its own — **a verifier MUST also validate the packet's own
consistency rules**, which reject that disagreement
([`lib/validator.mjs`](../lib/validator.mjs); see the
`disagreeing-exact-amount` example).

### UTC timestamps

A timestamp is committed as RFC 3339 with the `Z` designator, the fractional
part present only when non-zero and never carrying trailing zeros:
`2026-07-10T09:15:41.5Z`, `2026-07-10T09:15:41Z`.

`2026-07-10T09:15:41.000Z` and `2026-07-10T09:15:41Z` denote the same instant
and commit identically. A local-offset form (`+03:00`) is **refused rather than
converted**: this contract exports UTC, and converting silently would hide a
producer defect instead of surfacing it.

The rule is deliberately **lexical**: it fixes the grammar and the spelling,
not the calendar. Whether an instant exists is the packet schema's business
(`date-time` format); a commitment reproduces what the producer wrote, and a
runtime that reinterpreted a date here would be committing something other
than the record.

When normalizing an exported packet, every member whose name ends in `AtUtc` is
a timestamp; no other string is reinterpreted.

## 4. Commitment kinds and domain separation

The hashed byte string is:

```
"pruvz.ai/commitment" 0x00 <commitmentVersion> 0x00 <kind> 0x00 <canonical JSON>
```

`0x00` cannot occur in the tag, the version or a kind, so no combination of
header fields can be re-read as another. The header is what keeps an evidence
item's commitment from ever being mistaken for a packet's, or a version-1
commitment for a future version's.

`commitmentVersion` is `1`. The kinds are closed:

| Kind | Covers |
|---|---|
| `evidence-item` | One append-only evidence record — the unit written once and never mutated |
| `evidence-packet` | One exported Evidence Packet: the action record and its complete timeline |

An unrecognized kind is refused when a commitment is produced. An unrecognized
**version or digest suite is refused when one is read**: anything that takes a
commitment version from a document — a future signed envelope, a verifier —
calls `requireSupported()` before trusting a byte of it, so a version-2
commitment is never quietly evaluated under version-1 rules. There is no
default and no best-effort mode.

Both kinds share one document shape:

```json
{
  "binding": { "actionId": "act_…", "tenantId": "tenant-…" },
  "content": { }
}
```

The **binding** is the trust domain. A packet does not carry its tenant, and
evidence is only meaningful inside the tenant that produced it, so the tenant
and the action are committed alongside the content — the same content under
another tenant is a different commitment.

For `evidence-item`, `content` is the evidence record: `clientOperationId`,
`evidenceId`, `occurredAtUtc`, `payloadMetadata`, `recordedAtUtc`, `runId`,
`schemaVersion`, `sequence`, `source`, `sourceReference`, `summary`,
`trustLevel`, `type`. Every one of them must be present.

For `evidence-packet`, `content` is the normalized packet document (§3).

## 5. Digest

| Suite id | Digest | Printed form |
|---|---|---|
| `sha-256` | SHA-256 of the byte string in §4 | `sha256:` + 64 lowercase hex digits |

The suite id is explicit and closed so that adopting a future suite is a
recorded decision rather than a silent default. Digest algorithms come from the
platform's maintained cryptographic library; this repository implements no
cryptographic primitive of its own.

## 6. Failing closed

Every refusal carries a stable code, because two runtimes agreeing that
something is invalid is only meaningful if they agree *why*:

| Code | Refused because |
|---|---|
| `NON_INTEGER_NUMBER` | A number that is not an exact integer reached the document |
| `INTEGER_OUT_OF_RANGE` | An integer outside ±(2⁵³−1) |
| `NON_CANONICAL_DECIMAL` | Text that is not an exact decimal (exponent, plus sign, leading zeros, separators) |
| `NEGATIVE_ZERO` | `-0`: zero has one spelling |
| `NON_UTC_TIMESTAMP` | Not RFC 3339 with a `Z` designator |
| `MONEY_WITHOUT_EXACT_AMOUNT` | A money value carrying only the JSON number (format before `1.4.0`) |
| `INVALID_CURRENCY` | Not a three-letter uppercase ISO 4217 code |
| `INVALID_MONEY` | Not a money value where one was required, or a money value carrying a member beyond `amount`, `amountExact` and `currency` |
| `LONE_SURROGATE` | Text that is not well-formed Unicode |
| `UNKNOWN_KIND` | A commitment kind this version does not define |
| `UNKNOWN_COMMITMENT_VERSION` | A declared commitment version this implementation does not speak |
| `UNKNOWN_DIGEST_SUITE` | A digest suite this version does not define |
| `MISSING_BINDING` | No tenant or no action to bind the commitment to |
| `MISSING_FIELD` | A covered field is absent, which would shrink what is committed |
| `INVALID_DOCUMENT` | The input is not the document shape the kind requires |
| `UNSUPPORTED_VALUE` | A value outside the canonical value model — including a runtime object that is not plain data, which would commit as `{}` |

## 7. Golden vectors and the second runtime

[`commitment/v1/golden-vectors.json`](../commitment/v1/golden-vectors.json) is
the published agreement point. It carries, for each vector, the input and the
exact canonical bytes — and, for commitments, the digest:

| Group | Covers |
|---|---|
| `decimals` | Money normalization, including values no double can hold |
| `timestamps` | UTC normalization and fraction trimming |
| `canonicalization` | Member order, nesting, arrays, Unicode and escaping, null and empty values, safe integers, integer spellings, the binding shape |
| `commitments` | Whole documents of both kinds, including a complete exported packet |
| `rejected` | Every refusal above, with the code each runtime must report |

Two independent implementations must reproduce them: the reference
implementation in this repository, and the .NET implementation in `pruvz-core`,
which vendors this file by exact hash and runs the same assertions. Neither is
authoritative alone — agreement between them is what makes the format
verifiable rather than merely specified. A cross-runtime check that only one
implementation passes is a defect in the specification, not in the other
runtime.

A vector carries its document either as a value or, where the *spelling* of a
number is the point, as **raw JSON text** (`documentJson`): a parsed vector file
can no longer tell `5.0` from `5`, so those vectors are published as text and
each runtime parses them with its own parser — which is precisely what they
exist to compare.

Two cases are deliberately not shared vectors, because no JSON file can carry
them: a **lone surrogate**, which cannot round trip through a JSON file in
every runtime, and a **non-plain runtime object** (a date object, a class
instance) in a runtime whose value model can express one. Each implementation
proves natively the refusals its own value model can reach.

Directory `commitment/v1/` is immutable in the same way a released schema
directory is. A change to these rules is a new commitment version, never an
edit here.
