# External Anchoring, format version 1

This document specifies how a Pruvz **signed checkpoint** and a Pruvz **signed
trust-registry document** are witnessed outside the deployment that produced
them, so that a privileged local rewrite of history becomes detectable by
someone who was never asked to trust that deployment.

The reference implementation is [`lib/anchoring.mjs`](../lib/anchoring.mjs) and
the published cross-runtime golden vectors are
[`anchoring/v1/golden-vectors.json`](../anchoring/v1/golden-vectors.json).
`anchoring/v1/` is immutable exactly like a released schema directory,
`commitment/v1/`, `trust-registry/v1/` and `evidence-log/v1/`.

A packet still carries none of this. A Public Evidence Packet has no anchor,
no receipt and no witness time; anchors are fetched from the deployment that
issued them, exactly like seals, proofs and checkpoints.

## 1. What anchoring adds, and what it cannot add

[`docs/EVIDENCE-LOG.md`](EVIDENCE-LOG.md) §9 states the gap this document
closes, and states it as a limitation of that format:

> a deployment that signs a fork and shows each half to a different audience is
> detected only when the two audiences compare checkpoints.

An external witness removes the need for two audiences to find each other. A
third party that neither operates nor trusts Pruvz records that *these exact
bytes existed at this time*; a second, contradictory history cannot also have
been recorded, and the fork becomes visible to a single verifier holding a
single receipt.

Three limits are part of the format, not caveats bolted onto it:

- **A witness proves existence no later than the witness time.** It says the
  bytes existed by then. It says nothing about the `issuedAt` a checkpoint
  asserts about itself, or the `committedAt` a seal asserts about itself, both
  of which remain self-asserted exactly as their own formats state. A record
  anchored at 10:00 may have been produced at 09:00 or at 09:59; the anchor
  bounds one end and only one end.
- **A witness proves nothing about the world.** The evidence log's honesty
  note applies unchanged: an externally witnessed append-only log of false
  records is an externally witnessed append-only log of false records.
- **A witness is only as independent as the authority that issued it.** An
  anchor names which trust domain produced it, and a verifier reports the
  anchors that are actually present. Neither this format nor any deployment
  may describe a record as *anchored* on the strength of an anchor that is
  pending, failed or absent — §6, and the product's assurance-profile rule
  that forbids a `FULLY_VERIFIED` verdict without one.

## 2. Two subjects, never one record at a time

Anchoring is applied to **aggregate** documents only. This is a privacy rule
before it is a cost rule (§8), and the format admits exactly two subject kinds:

| `subject.kind` | The bytes witnessed | Why this subject |
| --- | --- | --- |
| `log-checkpoint` | One signed checkpoint — `{ checkpoint, signature }` | A checkpoint already covers every leaf in the tree at its size. Witnessing it witnesses all of them at once, and the batching bounds of [`EVIDENCE-LOG.md`](EVIDENCE-LOG.md) §5 decide how many. |
| `trust-registry` | One signed registry document, without its attestations — `{ manifest, signatures }` | A key history that is signed but never published can still be shown privately to one audience. Witnessing the document is what makes *published* mean something ([`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §8). |

There is deliberately **no per-evidence-record anchor and no per-tenant
anchor**. A public witness that received one anchor per record would publish
the shape of a tenant's activity — its volume, and the times of day it works —
without ever receiving a single identifier. The aggregate subject is what
keeps that from being derivable, and a deployment may not add a narrower one.

The trust-registry subject deliberately **excludes** `attestations`. That
member is where the receipt is later carried (§7), and a subject that included
it could never be witnessed: the bytes would have to contain a receipt that
does not exist until after they are witnessed. Signatures are included;
attestations are not; §7 states the consequence.

## 3. The blinding nonce

Every anchor carries a **32-byte blinding nonce**, generated from a
cryptographically secure source, that is mixed into the imprint before it
crosses the boundary (§4).

The nonce is what makes the imprint an opaque value rather than a function of
the subject. Without it the imprint would be a deterministic digest of bytes,
and three things would follow:

- Two independent witnesses that both received the imprint of one checkpoint
  could tell they had witnessed the same thing, and a witness that received a
  deployment's whole checkpoint series could count it.
- Anyone who later obtained a candidate subject could confirm or refute it
  against a published imprint by recomputing — a dictionary test, and the one
  the privacy boundary names explicitly for low-entropy material.
- The imprint's opacity would rest on a property of what is inside the
  subject — for a checkpoint, an unpredictable ECDSA signature — rather than
  on the anchoring format itself. That is a real property, and it is not one
  a *format* should depend on: it holds only while every subject the format
  admits contains such a value, and it does not survive a signer whose
  signatures are predictable.

The nonce removes all three, and it costs 32 bytes.

**The blinding nonce is allocated once per anchor and never regenerated.**
It is stored with the anchor record and is required to derive the imprint, so
a verifier cannot check the binding without it, and a witness never receives
it. Regenerating it on a retry would change the imprint, which is exactly what
must not happen: a retried anchor must present the *same* bytes to the
authority, so that at-least-once delivery converges on one witnessed value.

The nonce is **not a secret in the cryptographic sense** — it is disclosed to
every verifier that receives the anchor record, and it protects the imprint
from a public observer, not from the recipient of the record.

### The two nonces are not the same nonce

RFC 3161 §2.4.1 has a nonce of its own, and it solves a different problem: it
binds one response to one request, so a captured response cannot be replayed
against a later request. It is chosen fresh for **every protocol request**,
including every retry, and it appears in the request and in the token.

| | Blinding nonce | Request nonce |
| --- | --- | --- |
| Purpose | Correlation and dictionary resistance at the boundary | Request/response binding, replay resistance |
| Layer | Pruvz anchoring format | RFC 3161 transport |
| Width | Exactly 32 bytes | Per RFC 3161; at least 8 bytes here |
| Lifetime | Once per anchor, stable across every retry | Fresh for every request, including retries |
| Reaches the authority | Never | Always |

Conflating them breaks both properties at once: a blinding nonce that changed
per request would make retries anchor different bytes, and a request nonce
reused across requests would stop detecting replay.

## 4. The imprint

The imprint is the only value derived from a subject that ever crosses the
boundary:

```
anchorInput  =  <domain tag> NUL <anchor format version> NUL
                <32 raw bytes of blinding nonce>
                <canonical JSON of the subject>

anchorImprint = SHA-256(anchorInput)
```

| `subject.kind` | Domain tag |
| --- | --- |
| `log-checkpoint` | `pruvz.ai/log-anchor` |
| `trust-registry` | `pruvz.ai/trust-registry-anchor` |

Two more domain-separation tags, beside the commitment's
(`pruvz.ai/commitment`), the envelope's (`pruvz.ai/evidence-signature`), the
registry's (`pruvz.ai/trust-registry`), the leaf's
(`pruvz.ai/evidence-log-leaf`) and the checkpoint's
(`pruvz.ai/log-checkpoint`). Bytes hashed as an anchor imprint can never be
re-read as any of those, and a checkpoint anchor can never be re-read as a
registry anchor.

The header is UTF-8 text and the nonce is 32 **raw bytes**, not text. No
separator follows the nonce because its width is fixed by this format; a
format that admitted a variable-width nonce would need one, and this one may
not become that format without a new version.

Canonical JSON is RFC 8785, the same serializer every other layer of this
contract uses. The subject bytes are the canonical form of the whole subject
document — for a checkpoint, `{ checkpoint, signature }` exactly as the leaf
layer canonicalizes a seal; for a registry, `{ manifest, signatures }`.

**The imprint is 32 bytes and it is everything that leaves.** Not the subject,
not the nonce, not the origin, not a sequence number: the authority receives
the imprint and the request nonce, and no third value.

## 5. The anchor record

The record is the sidecar that lets a verifier check the binding. It is not
signed by Pruvz, and it does not need to be: everything it asserts is either
checkable against the authority's token or is inert.

```json
{
  "version": "1",
  "anchorId": "anc_2f8c1d0a",
  "subject": {
    "kind": "log-checkpoint",
    "origin": "pruvz.ai/evidence-log/dev",
    "subjectVersion": 3
  },
  "trustDomain": "digicert-tsa",
  "status": "ANCHORED",
  "blindingNonce": "…",
  "requestNonce": "…",
  "receipt": { "kind": "rfc3161-timestamp-token", "token": "…" }
}
```

| Member | Meaning |
| --- | --- |
| `version` | The anchoring format version, `"1"`. Refused before anything else is read if it is anything else — including absent, or present but not a string: `UNKNOWN_ANCHOR_VERSION`, never `ANCHOR_MALFORMED`. |
| `anchorId` | Opaque, assigned by the deployment, distinguishing one anchor of a subject from another. Two witnesses of one checkpoint, or a re-anchor after an authority changed its policy, are two records with two ids. |
| `subject.kind` | `log-checkpoint` or `trust-registry` — §2. |
| `subject.origin` | The log's origin, or the registry's issuer. Carries no tenant, action or payload identifier, by construction of both formats. |
| `subject.subjectVersion` | The checkpoint sequence, or the registry version. An aggregate counter in both cases: a positive integer no larger than 2^53 − 1, the canonical-JSON safe range every integer in this contract lives in — a larger one is `ANCHOR_MALFORMED` in every conformant runtime, not merely in ones whose native integers stop there. |
| `trustDomain` | Which independent trust domain issued the receipt — the name of a pinned verifier configuration, never a claim about it (§6). |
| `status` | `ANCHORED`, `PENDING` or `FAILED`. Explicit, and never inferred from the presence of a receipt. |
| `blindingNonce` | Canonical unpadded base64url of exactly 32 bytes — §3. Present in every status, because it is allocated before the request is made. |
| `requestNonce` | Canonical unpadded base64url of the RFC 3161 request nonce, at least 8 bytes — §3. Present in every status; replaced on every retry. |
| `receipt` | `{ kind, token }` when `status` is `ANCHORED`; `null` otherwise. `token` is base64 of the DER `TimeStampToken`. |

**No unsigned duplicates**, exactly as the envelope format states it. The
record deliberately does **not** carry the imprint, the witness time, the
authority's policy identifier or its name, even though all four would be
convenient to read: every one of them is inside the token, and a second copy
outside it is a value a verifier could read *instead of* checking. A verifier
derives the imprint from the subject and the nonce, and reads the time, the
policy and the authority from the token it verified.

`trustDomain` is the one label that is not in the token, and it cannot be used
to fake trust: it selects which pinned roots and which expected policy the
verifier applies (§6), so naming the wrong domain makes validation fail rather
than succeed.

Every text member is non-empty, at most 512 characters and printable ASCII —
the rule the envelope, the checkpoint and the manifest all apply, for the
reason they apply it.

## 6. Verifying a receipt

Verification is in two halves, and an implementation that does the first and
skips the second has checked arithmetic rather than trust.

**Half one — the binding.** Is this receipt about this subject?

1. Derive the imprint from `subject` and `blindingNonce` (§4).
2. Read the token's `messageImprint`. Its algorithm must be SHA-256
   (`ANCHOR_SUITE_UNSUPPORTED`) and its value must equal the derived imprint
   (`ANCHOR_BINDING_MISMATCH`).
3. Read the token's nonce. It must equal `requestNonce`
   (`ANCHOR_NONCE_MISMATCH`). A token carrying no nonce, when the record names
   one, is a refusal for the same reason.

**Half two — the authority.** Should this receipt be believed?

4. The token's signature verifies (`ANCHOR_SIGNATURE_INVALID`).
5. The signing certificate carries the **timestamping** extended key usage,
   `id-kp-timeStamping`, and carries it as a **critical**, sole EKU, per
   RFC 3161 §2.3 (`ANCHOR_UNTRUSTED_AUTHORITY`).
6. The certificate is within its validity period **at the token's `genTime`**,
   not at the time verification happens — otherwise every historical anchor
   would expire, which is the opposite of what an anchor is for
   (`ANCHOR_UNTRUSTED_AUTHORITY`).
7. The certificate chains to a root that this verifier has **pinned for this
   `trustDomain`**, not to whatever the host's ambient trust store happens to
   contain (`ANCHOR_UNTRUSTED_AUTHORITY`).
8. The token's policy OID is one the pinned configuration for this
   `trustDomain` admits (`ANCHOR_UNTRUSTED_AUTHORITY`).
9. The token is a well-formed `TimeStampToken` throughout, and any encoding
   this implementation cannot fully read is a refusal, never a shrug
   (`ANCHOR_RECEIPT_MALFORMED`).

Rule 7 is the one most easily got wrong. An ambient trust store differs
between a developer's laptop, a container image and a customer's host, so a
verifier relying on it would give three answers to one question, and would
trust several hundred authorities to say when Pruvz's history existed. The
pinned root is part of the verifier's configuration, alongside the registry
pin, and comes from the same kind of out-of-band channel
([`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §5).

### What the reference implementation does and does not do

[`lib/anchoring.mjs`](../lib/anchoring.mjs) implements **half one** in full,
plus the structural reading of the token that half one requires: it walks the
DER of a `TimeStampToken` and extracts `messageImprint`, `nonce`, `genTime`
and the policy OID. That is the half that is *Pruvz-specific* — the imprint
derivation is a composition this contract defines, and two runtimes must agree
on it byte for byte, which is what the vectors assert.

It deliberately does **not** implement half two. CMS signature verification
and X.509 path validation are published standards with maintained
implementations in every runtime this contract targets — `SignedCms` and
`X509Chain` in .NET, the platform's CMS and path-validation libraries
elsewhere — and this repository's rule against home-grown cryptography applies
exactly here. `readTimestampToken` reads a token; it does not verify one, its
documentation says so, and no caller may treat a successful read as a verified
anchor.

An implementation that ships half one alone is not a verifier. It has
established that a receipt is *about* a subject, and nothing at all about
whether the receipt is genuine.

### Where the two halves make runtimes disagree, on purpose

A token whose signature bytes were altered still **binds**: its
`messageImprint` is untouched, so half one has nothing to object to. The
reference implementation therefore accepts it, and a half-two implementation
must refuse it. That is not a defect in either — it is the boundary, and
`anchoring/v1/golden-vectors.json` publishes it as its own `runtimeDivergence`
section rather than as an agreement case, because calling it agreement would
misstate what half one establishes.

One practical consequence for implementers. On some platforms the two halves
are **not separable at the token level**: .NET's
`Rfc3161TimestampToken.TryDecode` verifies the CMS signature as part of
decoding and simply returns false for a bad one, so a runtime built on it
cannot distinguish *unreadable* from *not genuine* without decoding twice —
once with a CMS reader that does not verify, once with the verifying decoder.
Such a runtime must still refuse; only the reason code may differ, and the
vectors say which codes are acceptable. Refusing more than half one refuses is
always safe. Refusing less is not, and no implementation may report
`authorityVerified` unless it actually performed half two.

## 7. The trust-registry witness

[`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §2 defines a document as
`{ manifest, signatures, attestations }` where only `manifest` is signed, and
§8 states that attestations are never trusted by the chain rules because a
publication reference is a *pointer* — the commit id does not exist until
after the document is committed, so nothing about it is evidence.

A witness receipt lands in `attestations.witnesses`, the seam left empty by
the registry format, and it is a different kind of object from a publication:

- A publication reference is a pointer, checkable only by fetching what it
  points at and recomputing a digest.
- A witness receipt is **self-contained evidence**: it cryptographically binds
  the document's own bytes to a time, and §6 checks it without fetching
  anything.

This does not weaken the registry rule, and implementations must keep the two
apart. `acceptChain` still ignores attestations entirely — rollback, fork and
substitution are decided by the signed manifest chain and by nothing else, and
a witness receipt neither adds to nor subtracts from that decision. Anchor
verification is a **separate, explicit step** a caller performs on top of an
already-accepted chain. A design where a witness could rescue a manifest the
chain refuses would have made the witness a second, weaker root of trust.

Each entry of `attestations.witnesses` is an anchor record (§5) whose
`subject.kind` is `trust-registry`, whose `subject.origin` is the manifest's
`issuer` and whose `subject.subjectVersion` is its `registryVersion`. The
subject bytes are `{ manifest, signatures }` of the document the entry sits
in — which is why the subject excludes attestations (§2), and why a document
may gain a witness after publication without any byte of its signed manifest
changing.

## 8. The privacy boundary

Nothing that identifies a customer, a tenant, an action, an evidence record, a
connector or an amount may cross to an external authority. Under this format
that is not a discipline anyone has to maintain; it is a consequence of what
crosses:

- The authority receives the **imprint** — 32 bytes — and the **request
  nonce**. Nothing else is transmitted.
- The imprint is a digest over a blinded, aggregate subject, so it is neither
  a dictionary target (§3) nor correlatable between authorities.
- Both admissible subjects are aggregate by construction. A checkpoint carries
  origin, size, head, sequence, issue time, signer and profile — the evidence
  log's closed member set, which has no tenant, action or payload member. A
  registry manifest carries a key history, which has none either.

**The residual leak, stated rather than omitted.** A public authority that
receives a deployment's anchors over time learns how many checkpoints that
deployment issued and when. Where the batching bounds are known, that bounds
total sealed volume across all tenants. It does not reveal which tenants
exist, how activity divides between them, or that any particular tenant did
anything — those would need a per-tenant subject, which §2 forbids. A
deployment that considers even aggregate timing sensitive should anchor to an
authority it or its customer operates (a customer-owned immutable store) in
place of a public one; the format is indifferent to which authority is used
and reports the ones actually present.

## 9. Retention and deletion

Anchoring is compatible with deletion **because nothing deletable is ever
anchored**. The imprint is derived from a checkpoint or a key history, neither
of which contains payload, so no external record can outlive a deletion
obligation or make one impossible to honour.

What survives a deletion is a proof that *some* bytes existed at a time. The
evidence log already states the corresponding fact for a leaf whose sealed
record was deleted — it "still proves *a* record was there and unchanged; what
it was is gone". An anchor adds a witnessed time to that and nothing more.

Two rules follow, and both are requirements on implementations rather than
observations:

- **A commitment is not automatically non-personal data.** A digest of
  personal data is still derived from it, may be re-identifiable where the
  input space is guessable, and remains subject to the retention policy that
  governs it. No implementation, document or interface may state or imply that
  hashing removes an obligation. Retention of commitments and proofs is a
  policy decision that has to be made and recorded, not one this format
  answers.
- **Deleted payload must never be described as recoverable.** A verifier that
  can check an anchor over history whose payload is gone must say exactly
  that — the integrity of the history is intact and the content is
  unavailable — and must never present the surviving proof as though the
  content could be reconstructed from it. It cannot.

## 10. Refusal codes

Both runtimes refuse the same input with the same code — that is what the
golden vectors assert. The first seven are produced by the reference
implementation; the last two belong to half two of §6 and are produced by an
implementation that performs it.

| Code | Meaning |
| --- | --- |
| `UNKNOWN_ANCHOR_VERSION` | A format version this implementation does not speak — including absent, or not a string — refused before anything else is read. |
| `ANCHOR_MALFORMED` | A record that is not what the format allows: unknown or missing members, a bad status, a nonce of the wrong width or encoding, a receipt present on a non-anchored record or absent from an anchored one. |
| `ANCHOR_RECEIPT_MALFORMED` | A receipt that is not a well-formed RFC 3161 `TimeStampToken`, or that this implementation cannot fully read. |
| `ANCHOR_SUITE_UNSUPPORTED` | A `messageImprint` under a digest algorithm this format does not define. |
| `ANCHOR_BINDING_MISMATCH` | The token's `messageImprint` is not the imprint derived from this subject and this blinding nonce. |
| `ANCHOR_NONCE_MISMATCH` | The token's nonce is not the record's `requestNonce`, or is absent. |
| `ANCHOR_NOT_PRESENT` | An anchor was required, and this record's status is `PENDING` or `FAILED`. Never `FULLY_VERIFIED` on this path. |
| `ANCHOR_SIGNATURE_INVALID` | The token's signature does not verify. |
| `ANCHOR_UNTRUSTED_AUTHORITY` | Extended key usage, validity at `genTime`, chain to a pinned root, or policy — §6 rules 5 to 8. |

## 11. What this does not do

- **No proof of `committedAt` or `issuedAt`** — §1. A latest-existence bound
  is what a timestamp is, and stating it as anything stronger would be false.
- **No anchoring of unsealed or uncheckpointed records.** A record that was
  never sealed has no leaf; a leaf not yet covered by a checkpoint is not yet
  in an anchored tree. Both are "not yet provable", never "proven".
- **No packet changes.** The Public Evidence Packet schema is untouched;
  packets carry no anchor whatever format they declare (`1.5.0` at this writing).
- **No verifier product.** How an offline verifier presents an anchor, and how
  it weighs a missing one, is a later, separately released capability. This
  document defines the format and the checks; it does not ship the tool.
- **No trust in an authority this format chose.** The pinned roots and the
  admissible policies are the verifier's configuration, not this contract's.

## 12. The golden vectors

[`anchoring/v1/golden-vectors.json`](../anchoring/v1/golden-vectors.json)
publishes two layers, in the same convention as the commitment, registry and
evidence-log vectors:

- **Deterministic material** — subjects, blinding nonces, the exact
  `anchorInput` bytes and the resulting imprints for both subject kinds — must
  be reproduced **byte for byte** by any runtime. This is the layer that makes
  the format a contract rather than an implementation detail.
- **Receipt material** — a real RFC 3161 timestamp token obtained from a
  public authority over a published imprint, plus the refusal cases: a
  mismatched binding, a mismatched and an absent nonce, an unsupported digest
  algorithm, a truncated and a structurally corrupted token, malformed records,
  an unknown version, and a receipt required from a pending anchor — must be
  read or refused **identically, with the same reason code**.

`bindingCases` and `refusals` are the agreement points: every conformant
runtime behaves identically on them. `runtimeDivergence` is the opposite — the
single published case where a half-one and a half-two implementation **must**
differ, carrying what each is required to do. It is a separate section for a
reason: a reader scanning the vectors must not be able to mistake the one
disagreement for one more thing everybody agrees about.

The subjects reuse the published checkpoint and registry documents from the
evidence-log and trust-registry vectors, so no new fictitious identifier is
introduced and none of the real kind appears anywhere. The real token embeds
the authority's certificate chain and is published as received; its signature
belongs to an authority, so it can be verified but never regenerated, and
`anchoring/v1/` is therefore immutable.
