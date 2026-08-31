# Pruvz Public Evidence Packet

The open, versioned export contract for one business action recorded by [Pruvz](https://pruvz.ai), its verification state and its ordered evidence — published as a JSON Schema, with synthetic examples and a local structural validator you can run without a Pruvz account, an API key, or any connection to Pruvz services.

[Pruvz](https://pruvz.ai) independently verifies the business outcomes of AI agent actions against systems of record and keeps the evidence: what the agent saw, what policy applied at decision time, what the agent claimed, and what the systems of record actually confirmed.

## What this repository is — and is not

**It is** the public export contract: the schema of the Public Evidence Packet that the current Pruvz product demonstration exports, derived field-for-field from the product API's wire contract, plus everything needed to inspect and validate that contract offline. How the schema is kept true to the product — and the repeatable path from a live run to a conforming packet — is documented in [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

**It is not** the complete internal product model, and it contains none of the proprietary product implementation: no verification logic, no system-of-record connectors, no policy evaluation engine, and no internal service code. Internal, operational and sensitive fields are deliberately absent from the public contract. Conversely, this schema declares **no** field, guarantee or capability that the current product demonstration does not actually export.

## The packet

A Public Evidence Packet is one JSON document describing one recorded business action, its verification state and its evidence, assembled from the two public views of the Pruvz product API. A packet may describe any verification state — verified, mismatched, failed or still pending; only a `VERIFIED` status is an independently confirmed outcome.

The packet's parts:

| Packet part | Mirrors |
|---|---|
| `action` | The action details view (`GET /api/actions/{actionId}`): business identity, the two separate state machines (execution vs. verification), the embedded immutable decision-time Policy Snapshot, and the three deliberately separated value groups — the server-derived expectation, the agent's unverified claim, and what independent read-back actually observed. |
| `evidence` | The ordered evidence timeline (`GET /api/actions/{actionId}/evidence`): every append-only evidence item in sequence order, each with its server-assigned trust level. |
| `packetFormatVersion` | Metadata of the packet file itself — the format release it conforms to. |

Schemas live in [`schema/v1.5.0/`](schema/v1.5.0/) (current release; [`schema/v1.4.0/`](schema/v1.4.0/), [`schema/v1.3.0/`](schema/v1.3.0/), [`schema/v1.2.0/`](schema/v1.2.0/), [`schema/v1.1.0/`](schema/v1.1.0/) and [`schema/v1.0.0/`](schema/v1.0.0/) remain published and immutable):

- [`evidence-packet.schema.json`](schema/v1.5.0/evidence-packet.schema.json) — the packet envelope
- [`action.schema.json`](schema/v1.5.0/action.schema.json) — the action record
- [`evidence.schema.json`](schema/v1.5.0/evidence.schema.json) — the evidence timeline

Field-by-field meaning, every enum value, and the type-to-trust mapping are documented in [`docs/FIELDS.md`](docs/FIELDS.md). Versioning and compatibility rules are in [`docs/VERSIONING.md`](docs/VERSIONING.md). How one logical record becomes one deterministic byte string — the canonical commitment and its cross-runtime golden vectors — is specified in [`docs/COMMITMENT.md`](docs/COMMITMENT.md). How a signing key is recognized without asking the Pruvz deployment — the pinned root, the signed key history, rotation and time-aware revocation — is specified in [`docs/TRUST-REGISTRY.md`](docs/TRUST-REGISTRY.md). How a sealed record becomes a leaf of an append-only Merkle log, and how signed checkpoints with inclusion and consistency proofs make deletion, insertion, reordering and forked history detectable, is specified in [`docs/EVIDENCE-LOG.md`](docs/EVIDENCE-LOG.md). How a checkpoint or a key history is witnessed outside the deployment that produced it, under a blinding nonce that keeps the witnessed value opaque and uncorrelatable, is specified in [`docs/ANCHORING.md`](docs/ANCHORING.md).

## Validate a packet locally

Requires Node.js 18 or newer. Everything runs on your machine: the validator reads the local schema files, performs the validation in-process, and sends nothing anywhere — no telemetry, no packet contents, no phone-home of any kind.

Validation has two layers: JSON Schema validation, then packet-level consistency checks for the cross-object rules JSON Schema cannot express — the action and the timeline must name the same `actionId`, timeline sequences must be unique, ascending and contiguous from 1, evidence ids must be unique, the review block and review state must agree with the timeline's `HUMAN_REVIEW_DECISION` items (the decision history is exactly those items, in order, and the review state is where the latest decision left it), and execution state must agree with its timestamps and with the verification state. A third-party validator using the schema files alone will not catch that second layer; the schemas document it, this validator enforces it.

```bash
npm ci
npm run validate -- examples/valid/verified-refund.packet.json
```

Validate several files at once (the command exits non-zero if any file fails):

```bash
npm run validate -- examples/valid/*.packet.json
```

Run the automated tests proving the samples and validator behave as documented:

```bash
npm test
```

Compose a packet from the two saved API responses of a live product run (see [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md)):

```bash
npm run compose -- action.json evidence.json my-action.packet.json
```

## Verify a packet cryptographically — offline

Beyond structural validation, this repository ships the **independent offline verifier**: it checks an exported packet against the cryptographic material the producing deployment served — evidence seals, the append-only log’s inclusion and consistency proofs, signed checkpoints, the published trust-registry chain, and external anchors where they exist — and answers with a dimensional assurance report, never a bare boolean. The specification, the bundle format, every reason code and the verdict semantics are in [`docs/VERIFIER.md`](docs/VERIFIER.md); the published cross-runtime cases live in [`verifier/v1/`](verifier/v1/).

The trust anchor is a pinned `{ issuer, root }` established out of band ([`docs/TRUST-REGISTRY.md`](docs/TRUST-REGISTRY.md) §4) — never taken from the bundle, never fetched from the website. Everything runs on your machine, offline: verifying a Pruvz record must never depend on asking Pruvz.

```bash
# Compose a verification bundle from the saved API responses of an export session
npm run bundle -- ./export-dir verification.bundle.json

# Verify it against your pinned trust anchor (and, optionally, pinned TSA roots)
npm run verify -- verification.bundle.json \
  --issuer pruvz.ai --root sha256:<pinned-root-thumbprint> \
  --tenant <your-tenant> --tsa-roots tsa-roots.pem --state verifier-state.json
```

Exit codes: `0` FULLY_VERIFIED, `3` PARTIALLY_VERIFIED (nothing failed, something could not be checked — absent anchors, missing material, a pre-1.5.0 packet), `1` NOT_VERIFIED (something checked and failed). A valid signature with missing required anchor, consistency or trust material is never reported as fully verified. `--state` keeps what the verifier accepted across runs, which is what turns a rolled-back or forked history into a refusal instead of a surprise.

## Break it yourself — three independent verifiers, one answer

Since release `1.5.1` (PRUVZ-97) this repository carries the **adversarial conformance suite**: [`conformance/v1/`](conformance/v1/) publishes 41 frozen attack cases — tampered records, replayed seals, substituted signing keys, rolled-back registries, forked and shrunken Merkle histories, swapped and corrupted anchor receipts, assurance-profile downgrades — and **three full, independent verifier implementations** must produce the identical verdict, reason codes, dimension statuses and returned state on every one of them: the Node reference in [`lib/`](lib/), a .NET 8 implementation in [`conformance/dotnet/`](conformance/dotnet/) and a Python implementation in [`conformance/python/`](conformance/python/). Each covers the complete chain — canonicalization, ES256, key lifecycle, Merkle proofs, stateful fork detection and RFC 3161 authority verification — and none shares code with the others. [`docs/CONFORMANCE-SUITE.md`](docs/CONFORMANCE-SUITE.md) is the specification.

Reproduce a few of the published failures yourself, through the same CLI a customer runs:

```bash
npm ci
npm run attack-demo
```

That extracts three frozen adversarial bundles and verifies each against the published pins:

1. **A tampered record** (`mutated-evidence-field`) — one summary edited after sealing → `NOT_VERIFIED`, `COMMITMENT_MISMATCH`.
2. **A forked log history** (`checkpoint-fork-held-state`) — a second, *genuinely signed* checkpoint at an already-held sequence, refused only because the verifier kept state → `NOT_VERIFIED`, `CHECKPOINT_FORK`.
3. **A substituted signing key** (`substituted-registry`) — a complete, internally consistent registry under a different root; everything verifies under *its* root and nothing verifies under the pin → `NOT_VERIFIED`, `ROOT_MISMATCH`.

`npm run attack-demo -- <case-id>` runs any other published case; `npm run conformance` replays the whole suite through the Node implementation, and `npm run conformance:all` runs all three runtimes plus the cross-runtime comparison (needs .NET 8 and Python 3.12).

## Examples

The authored examples are synthetic — every identifier, amount and timestamp is fabricated. The captured example is real product output from the deterministic demo environment, which generates its own payments, tickets and refunds per run; nothing anywhere comes from a real customer, a real payment system, or real operational data.

- [`examples/captured/`](examples/captured/) — a packet composed from the two API responses of a live demo run with `npm run compose`: the conformance proof that real product output fits this schema. See [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

- [`examples/valid/`](examples/valid/) — one packet per verification path: [verified](examples/valid/verified-refund.packet.json), [outcome mismatch with a recorded human review decision](examples/valid/outcome-mismatch-decided.packet.json), [technical verification failure awaiting review](examples/valid/verification-failed.packet.json), [technical verification failure driven through the correction loop](examples/valid/verification-failed-resolved-externally.packet.json) (two recorded decisions, awaiting re-verification), [a reported correction independently confirmed](examples/valid/reverified-confirmed.packet.json), [a reported correction that re-mismatched](examples/valid/reverified-mismatch.packet.json), and [verification still pending](examples/valid/verification-pending.packet.json).
- [`examples/invalid/`](examples/invalid/) — twelve packets, each broken by exactly one documented defect (a fabricated outcome on a mismatch, an evidence item claiming a trust level its type cannot carry, a fabricated zero where "no amount" belongs, a displayed amount that disagrees with the exact one, and so on). See [`examples/invalid/README.md`](examples/invalid/README.md).

## What successful validation proves — and what it does not

Successful validation proves **conformance to the published packet format, and nothing more**: the document has the declared fields, types, enum values and internal consistency rules of the Public Evidence Packet format.

It does **not** prove:

- **Origin** — that the packet was produced by Pruvz rather than authored by hand.
- **Business accuracy** — that the recorded observations match what actually happened in any real system.
- **Cryptographic integrity or non-tampering** — that the packet was not modified after it was produced.

**A packet carries no signature, no hash chaining and no external anchor**, and validating one therefore proves none of them. Inside the product, evidence integrity rests on append-only, atomically-sequenced, server-assigned-trust storage; those properties belong to the running system and cannot be established after the fact from a JSON file alone.

Five of the pieces those capabilities need are now specified here, and all are deliberately separate from the packet format:

- **The canonical commitment** — [`docs/COMMITMENT.md`](docs/COMMITMENT.md). One logical record becomes one deterministic byte string and one digest, in every runtime; format `1.4.0` states every money amount exactly, as text, so that this is possible at all. A commitment answers *are these the exact values Pruvz committed to* — never *is what Pruvz recorded true*.
- **The public trust registry** — [`docs/TRUST-REGISTRY.md`](docs/TRUST-REGISTRY.md). A signed, versioned, hash-linked key history with a pinned out-of-band root, so that a signing key can be recognized without asking the Pruvz deployment whether its own key is genuine. It defines key rotation and time-aware revocation, and the rules that make a rolled-back, forked or substituted key history a refusal.
- **The append-only evidence log** — [`docs/EVIDENCE-LOG.md`](docs/EVIDENCE-LOG.md). Every seal becomes a leaf of a Merkle tree in the published RFC 6962 construction, tree heads are periodically signed as checkpoints, and inclusion and consistency proofs make deletion, insertion, reordering and forked history cryptographically detectable — for a verifier that holds checkpoint history.
- **The offline verifier** — [`docs/VERIFIER.md`](docs/VERIFIER.md). One entry point composes all of the above over an exported bundle and answers with a dimensional report: what was proven, what failed, and what could not be checked — each stated separately, with machine-readable reason codes. Format `1.5.0` is what makes the content dimension possible: the timeline now exposes every field the evidence-item commitment binds, so a seal’s digest is recomputable from the packet alone.
- **External anchoring** — [`docs/ANCHORING.md`](docs/ANCHORING.md). A signed checkpoint or a signed key history is witnessed outside the deployment that produced it, under a 32-byte blinding nonce, so that the 32 bytes reaching the witness identify nothing and correlate with nothing. It defines what may be witnessed (aggregate documents only, never one record and never one tenant), how a receipt is bound to its subject, and what still has to be checked before a receipt may be believed.

What that adds up to today, stated exactly: the product signs evidence commitments, publishes the key history that identifies the signer, appends every seal to an append-only log and periodically signs its head — so a seal fetched from a deployment can be checked offline against a pinned registry, and deleting, altering or reordering checkpointed records breaks proofs. All of it is checkable end to end with `npm run verify`, offline, against a pinned trust anchor. The anchoring **format** is specified and has a reference implementation, but **a format is not a deployment**: whether any given deployment actually anchors, and to which authority, is that deployment's configuration, and no packet or document here asserts that it does. A witness proves that bytes existed *no later than* the witness time — never that a self-asserted `committedAt` or `issuedAt` is exact, and never that records which were never sealed are covered by anything. Absolute language such as *tamper-proof* is never accurate here and is not used.

## Related material

- [Product demo](https://pruvz.ai/demo) — the end-to-end verification flow this contract is exported from.
- [Security architecture](https://pruvz.ai/security) — trust model, data access, and verification lifecycle.
- [A real captured packet, explained field by field](https://pruvz.ai/evidence-packet) — the captured packet from [`examples/captured/`](examples/captured/) published with its full technical walkthrough: every field group, the evidence timeline, and the verification sequence on the packet's own timestamps.

## License, contributing, security

- Licensed under the [MIT License](LICENSE).
- Contributions and release process: [`CONTRIBUTING.md`](CONTRIBUTING.md). Format changes follow the product — see [`docs/VERSIONING.md`](docs/VERSIONING.md).
- Reporting a vulnerability or a sensitive-data concern: [`SECURITY.md`](SECURITY.md).
