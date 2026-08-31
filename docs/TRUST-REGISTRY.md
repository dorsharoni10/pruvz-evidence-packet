# Public Trust Registry, format version 1

A **commitment** ([`COMMITMENT.md`](COMMITMENT.md)) answers *are these the exact
logical values Pruvz committed to?* A **signed envelope** adds *who committed to
them, for which record, under which assurance?*

Both leave one question open, and it is the one that decides whether either is
worth anything: **how do you know that key is Pruvz's?**

Until now the answer was "ask the Pruvz deployment", which is no answer at all —
a compromised deployment answers with a key of its choosing, and every signature
it ever made verifies perfectly against it. The trust registry is what makes
that question answerable without the deployment.

- Reference implementation: [`../lib/trust-registry.mjs`](../lib/trust-registry.mjs)
- Golden vectors: [`../trust-registry/v1/golden-vectors.json`](../trust-registry/v1/golden-vectors.json)

This repository publishes the **format, the rules and the vectors**. It does not
publish any deployment's actual keys: a live registry is published by the
deployment that owns it, through the channels agreed at onboarding (§5).

## 1. The trust model, stated honestly

No verifier can identify "the Pruvz signer" with literally zero bootstrap trust.
Anyone who claims otherwise has moved the trust somewhere and stopped mentioning
it. The goal is therefore **not** "trust nothing about Pruvz". It is exactly
three things:

1. **Bootstrap once, out of band.** A customer pins a root fingerprint at
   onboarding, from a channel that is not the running application.
2. **Make everything after that auditable against the pin.** Key rotations and
   revocations are published as a signed, versioned, hash-linked history.
3. **Never let mutable application state decide key history.** A verifier that
   already holds version *n* cannot be talked back to version *n−1*.

What this buys, precisely: a privileged Pruvz operator can still sign whatever
they like *going forward*, but they cannot **rewrite the past** — cannot
un-publish a key, cannot substitute a root without a pinned verifier noticing,
and cannot hide a revocation by serving an older manifest.

What it does not buy is in §10.

## 2. The published document

```json
{
  "manifest": {
    "formatVersion": "1",
    "issuedAtUtc": "2026-08-01T00:00:00Z",
    "issuer": "pruvz.ai",
    "keys": [ … ],
    "previous": { "digest": "sha256:…", "registryVersion": 1 },
    "registryVersion": 2
  },
  "signatures": [
    { "keyId": "https://…/keys/pruvz-trust-root/…", "signature": "…", "suite": "ES256" }
  ],
  "attestations": { "publications": [ … ], "witnesses": [] }
}
```

Only `manifest` is signed. `signatures` obviously cannot sign itself, and
`attestations` deliberately is not — §8.

| Member | Meaning |
|---|---|
| `formatVersion` | The rules this document follows. An unknown version is refused, never read as version 1. |
| `registryVersion` | A monotonic integer, starting at 1. This is the thing a rollback attacks. |
| `issuedAtUtc` | When the manifest was issued. Every `status` below describes this instant and no other. |
| `issuer` | The trust domain. Pinned alongside the root, so the right key under the wrong name is refused. |
| `previous` | `{ registryVersion, digest }` of the manifest immediately before, or `null` for the first. The hash link. |
| `keys` | The complete key history known at this version — never a delta. |

`previous.registryVersion` must be exactly `registryVersion − 1`. A history with
gaps is a history somebody could fill in later.

### Key entries

Each entry carries exactly these members, and a missing or extra one is a
refusal:

| Member | Meaning |
|---|---|
| `keyId` | The key identity, **byte-identical** to `signer.keyId` inside a signed evidence envelope. Printable ASCII, because an envelope admits nothing else. |
| `use` | `trust-root` or `evidence-signing`. See below — this is load-bearing. |
| `provider` | What actually holds the key, e.g. `azure-key-vault`. |
| `suite` | `ES256` or `ES384`. |
| `publicKey` | The public JWK: exactly `crv`, `kty`, `x`, `y`. |
| `thumbprint` | `sha256:` and the RFC 7638 thumbprint of `publicKey`, unpadded base64url. |
| `status` | `ACTIVE`, `RETIRED` or `REVOKED` — **as of `issuedAtUtc`**. |
| `validFromUtc` | When the key entered service. Never later than `issuedAtUtc`. |
| `retiredAtUtc` | When it left service, or `null`. |
| `revokedAtUtc` | When it must be treated as compromised, or `null`. |
| `revocationReason` | Prose, or `null`. Present only with `revokedAtUtc`. |
| `predecessorKeyId` | The key this one replaced, or `null`. Rotation lineage. |

**`use` separates two powers that must never meet.** A root key signs the key
history; an evidence key signs records. A root that could also seal evidence
would let whoever controls key history mint records. An evidence key that could
sign the manifest would let an application compromise rewrite which keys are
trusted. A verifier refuses each in the other's place, and the golden vectors
carry a genuine, perfectly valid signature for each mistake.

**The thumbprint is recomputed, never believed.** It is present because a pin is
taken over it and a human has to be able to read it out of the document — a
derivation that is checked, not a second source of truth. A declared thumbprint
that disagrees with the key beside it is `THUMBPRINT_MISMATCH`.

**A public JWK's member set is closed.** A thumbprint covers `crv`, `kty`, `x`
and `y` and nothing else, so an extra member would ride along un-thumbprinted
and a pin would not notice it. And `d` is refused outright: a runtime will
happily build a working *public* key from a private JWK, so everything would
look correct while a private key sat in a document this contract promises never
contains one.

**Coordinates are the curve's fixed width, zero-padded** (RFC 7518). A
coordinate trimmed of a leading zero byte thumbprints differently and would
break a pin for a reason nobody could see.

## 3. The signed bytes

```
"pruvz.ai/trust-registry" 0x00 <formatVersion> 0x00 <canonical JSON of manifest>
```

Canonical JSON is RFC 8785 over the value model of
[`COMMITMENT.md`](COMMITMENT.md) §1–2 — the same serializer, so there is one
canonicalization in this contract rather than three.

The domain tag differs from `pruvz.ai/commitment` and from
`pruvz.ai/evidence-signature`, so no byte string signed in one domain can be
re-read as a document of another. The version appears once, inside the signed
document, and the header is derived from it.

A manifest's **digest** is `sha256:` and 64 lowercase hex over exactly those
bytes. One byte string, one digest, one signature — so a `previous` link and a
signature can never disagree about which manifest they mean.

Signatures are ECDSA in the fixed-width IEEE P1363 form (`r || s`). DER is never
produced or accepted.

## 4. Pinning

A pin is two values:

```json
{ "issuer": "pruvz.ai", "root": "sha256:2A7ZGclH-8L7JIDz0YUHjYglAqsbs1_ugmLkP8tfMqQ" }
```

**Verification without a pin is refused** (`NO_TRUST_ANCHOR`). Not degraded, not
warned about — refused. A verifier with no anchor can only believe whatever key
history it was handed, which is precisely the failure this layer exists to
remove, and a permissive mode would quietly become the mode everyone uses.

`rootPinFromManifest` derives a pin from a manifest obtained out of band, and
**refuses a manifest declaring more than one active root** (`AMBIGUOUS_ROOT`):
pinning is a decision about one identity, and silently taking the first of
several would make a pin depend on array order.

## 5. Bootstrap channels

The root fingerprint must be obtainable through **more than the running
application**. A deployment publishes it through at least two independent
channels agreed at onboarding — a public source repository or release, and the
onboarding document the customer signs, are the zero-cost pair.

The deployment's own `GET /api/trust-registry` and its website are legitimate
*distribution* channels and are never the *root* channel: they are exactly what
a pin exists to check. A verifier that would accept a new root because the
website served one has no pin at all.

An externally witnessed registry — a transparency witness or notarisation
service — is a stronger channel and a **cost-gated** one. It is registered as
`CG-06` in the product's cost-gated capability registry and is `PLANNED` until a
provider acceptance run passes. Nothing here may be described as externally
witnessed until it is.

## 6. Rotation

Rotation is two published steps, and the order matters:

1. **Publish the successor beside its predecessor**, both `ACTIVE`, the
   successor naming the predecessor in `predecessorKeyId`. Only then may the
   product start signing with it.
2. **Retire the predecessor** once nothing signs with it any more.

Doing it the other way round would let a record be sealed by a key the current
manifest does not carry, and that record would verify against nothing.

**Normal rotation never invalidates historical evidence.** A seal made while a
key was `ACTIVE` stays fully valid after that key is retired; the verdict simply
carries `KEY_RETIRED_AFTER_SIGNING` as an informational note. A design where
rotation broke old evidence would make operators avoid rotating, which is the
opposite of the point.

## 7. Revocation, and why the answer is time-aware

Revocation says: *from this instant onward, treat this key as compromised.* It
is routinely **back-dated** to when a compromise is believed to have begun, so
the retirement and revocation windows can overlap. Where they do, revocation
wins — the stronger statement is the true one.

A seal is judged against the state of its key **at the moment it signed**, not
the status the latest manifest declares:

| When the seal was made | Verdict | Reason codes |
|---|---|---|
| Key active, still active | `VALID` | — |
| Key active, later retired | `VALID` | `KEY_RETIRED_AFTER_SIGNING` |
| Key active, later revoked | `PARTIAL` | `SIGNED_BEFORE_REVOCATION`, `COMMITTED_AT_SELF_ASSERTED` |
| At or after `revokedAtUtc` | `INVALID` | `SIGNED_AFTER_REVOCATION` |
| At or after `retiredAtUtc` | `INVALID` | `SIGNED_AFTER_RETIREMENT` |
| Before `validFromUtc` | `INVALID` | `SIGNED_BEFORE_KEY_VALID` |

Flattening those six into one boolean is exactly what this table exists to
prevent. The third row is the one worth reading twice: a seal made before the
declared compromise boundary is worth *something*, but the comparison is against
`committedAt`, **a time Pruvz asserted about itself**. A signer that was already
compromised could have back-dated it. That is why the verdict is `PARTIAL` and
why `COMMITTED_AT_SELF_ASSERTED` travels with it. An external witness of the
seal is what would settle it, and there is none yet.

**Timestamps are compared exactly, and not as they appear.** Canonical
timestamps omit a zero fraction, so a naive lexical compare puts `…:00Z` *after*
`…:00.5Z` — `Z` is greater than `.`. Implementations widen the fraction to a
fixed width before comparing, which keeps the comparison exact with no `Date`,
no millisecond truncation and no floating point anywhere near a security
boundary.

## 8. Rollback, forks and substitution

A verifier remembers the highest registry version it has accepted and that
manifest's digest. A manifest that verifies is not yet acceptable:

| Presented | Refusal |
|---|---|
| A lower registry version | `REGISTRY_ROLLBACK` |
| The same version, a different digest | `REGISTRY_FORK` |
| A version more than one step ahead | `REGISTRY_CHAIN_BROKEN` |
| A `previous` link naming a different document | `REGISTRY_CHAIN_BROKEN` |
| A manifest the pinned root did not sign | `ROOT_MISMATCH` |
| The right root under a different issuer | `ISSUER_MISMATCH` |
| A manifest altered after signing | `REGISTRY_SIGNATURE_INVALID` |

The rolled-back document is the interesting one: **it is not corrupt**. It was
signed by the real root and passes every structural rule. Only the history the
verifier already holds makes it a refusal — which is why the state has to be
kept, and why a verifier that starts fresh every time is not a verifier.

Being handed the manifest already held is neither an attack nor a change; the
state does not move and nothing is refused. The same applies to a served
**full history**: a deployment legitimately serves its documents from version
1, so manifests *below the held watermark* — the version the verifier's state
already recorded when the walk began — are verified but never judged as
rollback; the rollback presentation is a chain whose NEWEST document is older
than the held version (clarified under PRUVZ-97, whose conformance suite found
the earlier reading refusing every re-verification of a multi-version chain).
The tolerance is exactly that wide: a document older than an **earlier
document of the same served chain** is `REGISTRY_ROLLBACK` as before — a
deployment serves its history in order, and an out-of-order document whose
linkage was never walked is not waved through as if it had been.

**State belongs to the anchor that produced it.** The state records the
`{ issuer, root }` it was established under, and continuing it under a different
pin is refused — `ISSUER_MISMATCH` or `ROOT_MISMATCH` — before any version is
compared. Two roots are two histories, and their version numbers say nothing
about each other: without this rule a verifier handed state from another trust
domain would answer `REGISTRY_ROLLBACK`, or accept, for a reason that has
nothing to do with either of them.

**Attestations are never trusted here.** A publication reference cannot be
signed by the document it points at — the commit id does not exist until after
the document is committed. An attestation is therefore a *pointer*, checkable by
recomputing the digest of whatever it leads to, and never evidence that a
publication happened.

## 9. Verifying a seal

Verification takes the expected subject from the **caller**, never from the
envelope it is checking. A signature lifted from another tenant, another action,
another evidence item or another position on the timeline is perfectly valid; it
simply attests to something else.

The result is dimensional, because these are five questions and not one:

| Dimension | Answers |
|---|---|
| `keyIdentity` | Is this key in the published history, and is it an evidence key? |
| `signature` | Does the signature verify over the envelope's own bytes? |
| `keyLifecycle` | Where did the key stand when it signed? |
| `subject` | Is this a seal about the record I asked about? |
| `content` | Does it commit to the content I computed? |

Overall verdict: `VALID` (everything checked, everything holds), `PARTIAL`
(nothing failed, but something is weakened or was not checked) or `INVALID`.

**`PARTIAL` may never be reported as full verification.** A downstream verifier
maps `VALID` and only `VALID` onto its strongest result.

## 10. What this does not do

- **It does not verify content on its own.** `content` is `NOT_CHECKED` unless
  the caller supplies a commitment digest it computed **from the record**, and
  the verdict is then `PARTIAL` with `COMMITMENT_NOT_CHECKED`. A seal whose
  digest nobody compared proves origin and binding, not that the record still
  says what it said.
- **A Public Evidence Packet is not enough to compute that digest.** An evidence
  item's commitment covers `clientOperationId`, `payloadMetadata`, `runId` and
  `schemaVersion`, and the public timeline view carries none of them — it is a
  projection, deliberately. Closing that gap means either exporting the sealed
  record in its committed form or committing over the public view instead, and
  it is a decision for the offline-verifier work, not a change to make quietly
  here. Until then, an offline check of a packet plus its seal establishes
  origin, key trust and binding, and says so.
- **A self-signed root revocation is weak by nature.** A manifest announcing
  "this root is compromised" is signed by that root, because it is the only
  identity a pinned verifier will listen to — and whoever stole the key can make
  the same announcement. The recovery is a **new out-of-band pin**, never a
  silent substitution. Root rotation is representable in the format; performing
  one requires re-bootstrapping every pinned verifier, and that is the intended
  cost.
- **No external witness.** Nothing here proves the registry was published, only
  that it was signed and is internally consistent. An operator who never
  published could still serve a private history to one customer. Witnessing is
  `CG-06` and remains cost-gated.
- **No ordering or completeness proof for evidence.** A record can still be
  missing entirely; a seal proves nothing about records that were never sealed.
- **`committedAt` is self-asserted** — see §7.
- **No packet format change.** A packet — `1.5.0` included — carries no seal and no
  trust metadata. Seals are fetched from the deployment's own API and verified
  against a pinned registry; the packet format is untouched by this release.

## 11. The golden vectors

`trust-registry/v1/` is **immutable**, exactly like a released schema directory
and like `commitment/v1/`. Changing the rules means a new format version, never
an edit in place.

The vectors have two layers, and both matter:

- **Deterministic material** — thumbprints, canonical bytes, digests, the seal
  signing input. Any conforming runtime reproduces these byte for byte.
- **Signed material** — a five-version history that publishes, rotates in,
  retires out, revokes late and revokes early, plus a set of documents and seals
  that must be refused. Every runtime must reach the same verdict with the same
  reason code.

The keys are ephemeral NIST P-256 pairs generated once; the private halves were
never written anywhere and no longer exist. ECDSA is randomized, so regenerating
would produce different signatures — the published bytes are the agreement
point, and that is the whole purpose of freezing them.

The negative documents carry **genuine signatures over their own defective
bytes**, so each one proves its own rule rather than proving that a broken
signature fails. The single exception is the tampered-after-signing case, where
the broken signature *is* the rule.
