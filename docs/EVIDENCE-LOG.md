# Append-Only Evidence Log, format version 1

This document specifies the Pruvz append-only evidence log: how a sealed
evidence record becomes a leaf of a Merkle tree, how the tree head is
periodically signed as a **checkpoint**, and how **inclusion** and
**consistency** proofs let a verifier detect deletion, insertion, reordering
and forked history — cryptographically, without trusting the deployment that
serves the answers.

The reference implementation is [`lib/evidence-log.mjs`](../lib/evidence-log.mjs)
and the published cross-runtime golden vectors are
[`evidence-log/v1/golden-vectors.json`](../evidence-log/v1/golden-vectors.json).
`evidence-log/v1/` is immutable exactly like a released schema directory,
`commitment/v1/` and `trust-registry/v1/`.

A packet still carries none of this. A Public Evidence Packet has no leaf
hash, no proof and no checkpoint; proofs and checkpoints are fetched from the
deployment that issued them and checked against a pinned trust registry,
exactly like seals ([`docs/TRUST-REGISTRY.md`](TRUST-REGISTRY.md)).

## 1. What the log adds, stated honestly

A seal ([`docs/TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §9) answers *who
committed to this record, and to exactly what*. It cannot answer *and is the
record still there* — deleting a sealed record leaves every other seal
verifying perfectly, and nothing about the seals that remain says one is
missing. The log closes that gap:

- Every seal is appended, in issue order, as one leaf of a Merkle tree.
- The tree head is periodically signed as a checkpoint: "this log had
  `treeSize` leaves and head `rootHash`".
- An **inclusion proof** shows one specific leaf is at one specific position
  of a checkpointed tree.
- A **consistency proof** shows a later checkpoint's tree is an append-only
  extension of an earlier one — nothing already checkpointed was deleted,
  altered, reordered, or had anything inserted before it.

Two limits, stated because they are easy to over-claim:

1. **A checkpoint's `issuedAt` is self-asserted**, exactly like a seal's
   `committedAt`. Nothing here proves a checkpoint existed at the time it
   names. External witnessing and anchoring of checkpoints are a later
   product capability and nothing in this format may be described as
   anchored.
2. **The log preserves history; it does not make recorded facts true.** It
   covers exactly the records that were sealed into it, and capture fidelity
   remains the product's independent system-of-record read-back — a separate
   assurance dimension that no amount of hashing replaces.

And one detection honesty note: fork detection is only as strong as the
verifier's memory. A verifier that keeps no accepted-checkpoint state, or
only ever sees one checkpoint, cannot tell a fork from a history. The
acceptance rules in §7 are written for a verifier that holds state.

## 2. The tree construction is a published one

The tree composition is exactly the one published for Certificate
Transparency — RFC 6962 §2.1 and its successor RFC 9162 §2.1:

- The hash of a **leaf** is `SHA-256(0x00 ‖ leaf bytes)`.
- The hash of an **interior node** is `SHA-256(0x01 ‖ left ‖ right)`.
- The tree over `n > 1` leaves splits at `k`, the largest power of two
  strictly less than `n`; the head of the empty tree is `SHA-256("")`.
- Inclusion proofs are RFC 6962 `PATH(m, D[n])`, verified with the RFC 9162
  §2.1.3.2 algorithm. Consistency proofs are RFC 6962 `PROOF(m, D[n])`,
  verified with the RFC 9162 §2.1.4.2 algorithm.

This is a deliberate reuse of a widely analyzed, publicly documented
construction, chosen so any verifier can check the math against the public
literature. It is **not** a claim that Pruvz implements the Certificate
Transparency protocol, its log entry formats, its APIs or its ecosystem.
What goes into a leaf is Pruvz-specific and domain-separated (§3), and the
golden vectors include the published RFC 6962 known-answer test tree so both
runtimes prove they compute the standard construction, not a lookalike.

The one-byte `0x00`/`0x01` prefixes are load-bearing: they make it
impossible to present a leaf as an interior node or an interior node as a
leaf, which is the classic second-preimage confusion in Merkle trees.

## 3. The leaf

One leaf is one **seal, exactly as issued and stored**: the signed envelope
plus its signature, nothing else.

```
leaf bytes = "pruvz.ai/evidence-log-leaf" NUL <logFormatVersion> NUL <canonical JSON of { envelope, signature }>
leaf hash  = SHA-256( 0x00 ‖ leaf bytes )
```

- The canonical JSON is RFC 8785, produced by the same canonicalization as
  every other layer of this contract ([`docs/COMMITMENT.md`](COMMITMENT.md)).
- The domain tag `pruvz.ai/evidence-log-leaf` is a fourth domain beside the
  commitment's, the envelope's and the registry's: bytes hashed as a leaf can
  never be re-read as any of those.
- The member set is closed: exactly `envelope` and `signature`. The envelope
  must declare envelope version `1` and the signature must be unpadded
  base64url of exactly the envelope suite's width.
- The leaf includes the **signature**, not just the envelope, so the log
  witnesses both what was committed to and the signature that committed it.
  A seal whose signature was later swapped for another valid one hashes to a
  different leaf.

Because the envelope binds the commitment digest of the record, **mutating a
historical evidence record transitively invalidates its proofs**: the record
changes its commitment, the commitment changes the envelope, the envelope
changes the leaf hash, and the old inclusion proof now leads a hash that no
longer exists in any checkpointed tree.

The log stores leaf **hashes** forever; leaf **contents** are the sealed
records themselves. Tree heads are computed over the stored hashes, so a
tree whose old leaf contents were removed by retention still recomputes and
still proves consistency — retention removes payloads, never history.

## 4. The checkpoint

A checkpoint is the signed statement "the log named `origin` had `treeSize`
leaves and head `rootHash` when checkpoint number `checkpointSequence` was
issued". Its member set is closed:

| Member | Meaning |
| --- | --- |
| `version` | The evidence-log format version, `"1"`. Refused before anything else is read if it is anything else — including absent, or present but not a string: a document that names no version this implementation speaks is `UNKNOWN_LOG_VERSION`, never `LOG_MALFORMED`. |
| `origin` | The log's stable name. One log, one origin; a checkpoint from another origin is refused outright. Carries no tenant, action or payload identifier. |
| `checkpointSequence` | Strictly increasing issue counter, starting at 1. |
| `treeSize` | The number of leaves the checkpoint covers. |
| `rootHash` | `"sha256:"` then 64 lowercase hex digits — the tree head, suite named explicitly. |
| `issuedAt` | Canonical UTC timestamp. **Self-asserted**, like a seal's `committedAt`. |
| `signer` | Exactly `{ keyId, provider, suite }` — the same signer identification an envelope carries. |
| `assuranceProfile` | The profile actually in force when the checkpoint was issued — never a stronger one. |

The signed bytes are:

```
"pruvz.ai/log-checkpoint" NUL <version> NUL <canonical JSON of the checkpoint>
```

The version appears once, inside the signed document; the header names it by
derivation, never as a second unsigned copy. Everything security-relevant is
inside the signature: a transported checkpoint carries no unsigned metadata
for a verifier to read, so tampering changes the signed bytes and fails
signature verification rather than changing what the signature is understood
to mean.

Checkpoints are signed by an `evidence-signing` key from the published trust
registry, and the verifier resolves the key by the checkpoint's own
`signer.keyId` **through the pinned registry**, with the registry deciding
whether that key was trustworthy at the time — rotation, retirement and
time-aware revocation all apply exactly as they do to seals.

A signature is transported as **canonical** unpadded base64url: the decoded
bytes must re-encode to exactly the text received. A signature's final
character carries bits the signature itself does not use, so a lenient
decoder would accept several spellings of one signature; only one spelling is
a valid transported form, and the others are `MALFORMED_SIGNATURE`. The same
rule applies to the `signature` inside a leaf, which is hashed rather than
merely read.

## 5. Batching, not one-signature-per-record

Checkpoints are issued in bounded batches, controlled by two limits:

- `maxLeavesPerCheckpoint` — a checkpoint is issued once this many new
  leaves have accumulated, and
- `maxCheckpointInterval` — or once this much time has passed with at least
  one new leaf, whichever threshold is reached first.

Every leaf is therefore covered by a checkpoint within a bounded delay,
without a signature — or, later, an anchoring transaction — per record.
The limits are deployment configuration, not part of the signed format; what
the format guarantees is only that a leaf not yet covered by any checkpoint
has no inclusion proof *yet*, and a verifier must treat "not yet
checkpointed" as "not yet provable", never as "proven".

## 6. Proof verification

An inclusion proof is verified against `(leafHash, leafIndex, treeSize,
rootHash)`; a consistency proof against `(fromSize, fromRootHash, toSize,
toRootHash)`. Both are refusals-with-a-reason, never quiet booleans.

**`treeSize` and `rootHash` must be taken together, from one signed
checkpoint.** This is a hard verification requirement, not advice. The
published RFC 9162 algorithms bind the proof to the *(size, root)* pair; for
some index/size combinations the same path bytes verify under an adjacent
tree size, so a prover who is allowed to state the size independently of the
root could equivocate. A verifier never accepts a size or a root from the
prover: it accepts a checkpoint whose signature verifies under a
registry-trusted key, and then uses that checkpoint's `treeSize` and
`rootHash` as one inseparable pair. The same applies to consistency proofs:
both endpoints come from signed, accepted checkpoints.

What each failure means:

- An inclusion proof that fails says the leaf is not at that position of
  that checkpointed tree — the record was never in the log, is not where the
  log claims, or was altered after sealing.
- A consistency proof that fails says the later tree is not an extension of
  the earlier one — something already checkpointed was deleted, altered or
  reordered, or something was inserted before the old boundary. The golden
  vectors include one refusal vector for each of these tamper classes.

## 7. Accepting checkpoints: stale, fork, rollback

A verifier that holds the last checkpoint it accepted applies these rules to
every candidate, **after** validating it and verifying its signature:

1. **Origin** — a checkpoint whose `origin` differs from the accepted one is
   refused (`CHECKPOINT_ORIGIN_MISMATCH`). Two logs cannot vouch for each
   other.
2. **Stale** — a candidate with a *lower* sequence than the accepted one is
   refused as current (`CHECKPOINT_STALE`). A correctly signed, structurally
   perfect old checkpoint is still a refusal when presented as the present.
3. **Fork** — two checkpoints with the *same* sequence and different
   `treeSize` or `rootHash`, or a later checkpoint at the same tree size
   naming a different head, are a fork (`CHECKPOINT_FORK`). Neither document
   is individually "corrupt" — only held history reveals the contradiction.
4. **Rollback** — a later checkpoint covering *fewer* leaves is refused
   (`CHECKPOINT_ROLLBACK`). Append-only means the tree never shrinks.
5. **Growth needs proof** — a later checkpoint covering more leaves is
   accepted only with a consistency proof connecting the accepted head to
   the candidate head. Growth asserted without proof is refused
   (`CONSISTENCY_PROOF_INVALID`).

A verifier need not witness every checkpoint a log issues — sequences may
have gaps from its point of view — which is exactly why rule 5 demands a
consistency proof between *accepted* checkpoints rather than sequence
adjacency. Re-presenting the already-accepted checkpoint is idempotent.

## 8. Refusal codes

Both runtimes must refuse the same input with the same code — that is what
the golden vectors assert.

| Code | Meaning |
| --- | --- |
| `UNKNOWN_LOG_VERSION` | A format version this implementation does not speak — including one that is absent or is not a string — refused before anything else is read. |
| `LOG_MALFORMED` | A document that is not what the format allows: unknown or missing members, malformed hashes, timestamps or bounds. |
| `MALFORMED_SIGNATURE` | A signature that is not *canonical* unpadded base64url — it must re-encode to the text received — of exactly the suite's width. |
| `INVALID_PUBLIC_KEY` | A key that is not a valid public JWK for a suite this contract defines. |
| `INCLUSION_PROOF_INVALID` | The path does not lead this leaf to this root at this size. |
| `CONSISTENCY_PROOF_INVALID` | The proof does not show the new tree extends the old one. |
| `CHECKPOINT_SIGNATURE_INVALID` | The signature over the checkpoint does not verify under the resolved key. |
| `CHECKPOINT_STALE` | A checkpoint older than one already accepted, presented as current. |
| `CHECKPOINT_FORK` | Two correctly signed checkpoints that contradict each other. |
| `CHECKPOINT_ROLLBACK` | A later checkpoint whose tree is smaller — append-only violated. |
| `CHECKPOINT_ORIGIN_MISMATCH` | A checkpoint from a different log entirely. |

## 9. What this does not do

- **No anchoring, no witnessing, no timestamps anyone must believe.** A
  checkpoint proves internal consistency of a history; it does not prove
  when that history existed. Until checkpoints are externally witnessed, a
  deployment that signs a fork and shows each half to a different audience is
  detected only when the two audiences compare checkpoints (§1, honesty note).
  Witnessing is now specified separately, in
  [`docs/ANCHORING.md`](ANCHORING.md), and remains outside *this* format: a
  checkpoint is unchanged by being anchored, `issuedAt` stays self-asserted
  whether or not an anchor exists, and whether a deployment anchors at all is
  its own configuration.
- **No truth about the world.** §1's second limit, restated because it is
  the one most tempting to skip: an append-only log of false records is an
  append-only log of false records.
- **No packet changes.** The Public Evidence Packet schema is untouched;
  packets keep declaring `packetFormatVersion: "1.4.0"`. Proofs and
  checkpoints are fetched from the issuing deployment, like seals.
- **No claim of Certificate Transparency compliance** — §2.

## 10. The golden vectors

[`evidence-log/v1/golden-vectors.json`](../evidence-log/v1/golden-vectors.json)
publishes two layers, in the same convention as the commitment and registry
vectors:

- **Deterministic material** — the RFC 6962 known-answer test tree, leaf
  inputs and hashes for a synthetic eight-seal log, tree heads at every
  size, every inclusion path and every consistency proof for that log — must
  be reproduced **byte for byte** by any runtime.
- **Signed material** — checkpoints signed by an ephemeral key generated
  once (the private half no longer exists), an acceptance chain, and the
  refusal cases: deletion, insertion, reordering, wrong tree size, wrong and
  truncated proof paths, tampered leaf content, tampered and corrupted
  checkpoint signatures, stale, forked, rolled-back and wrong-origin
  checkpoints, growth without proof, and malformed documents — must be
  accepted or refused **identically, with the same reason code**.

The synthetic seals use the same fictitious identifiers as the registry
vectors; no real tenant, action or payload identifier appears anywhere in
the vectors, and none appears in a checkpoint by construction (§4).
ECDSA is randomized, so regenerating would produce different signatures;
the published bytes are what both runtimes must agree on, and
`evidence-log/v1/` is therefore immutable.
