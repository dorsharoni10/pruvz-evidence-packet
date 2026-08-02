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

Schemas live in [`schema/v1.0.0/`](schema/v1.0.0/):

- [`evidence-packet.schema.json`](schema/v1.0.0/evidence-packet.schema.json) — the packet envelope
- [`action.schema.json`](schema/v1.0.0/action.schema.json) — the action record
- [`evidence.schema.json`](schema/v1.0.0/evidence.schema.json) — the evidence timeline

Field-by-field meaning, every enum value, and the type-to-trust mapping are documented in [`docs/FIELDS.md`](docs/FIELDS.md). Versioning and compatibility rules are in [`docs/VERSIONING.md`](docs/VERSIONING.md).

## Validate a packet locally

Requires Node.js 18 or newer. Everything runs on your machine: the validator reads the local schema files, performs the validation in-process, and sends nothing anywhere — no telemetry, no packet contents, no phone-home of any kind.

Validation has two layers: JSON Schema validation, then packet-level consistency checks for the cross-object rules JSON Schema cannot express — the action and the timeline must name the same `actionId`, timeline sequences must be unique, ascending and contiguous from 1, evidence ids must be unique, a `DECIDED` review state and `HUMAN_REVIEW_DECISION` evidence must imply each other, and execution state must agree with its timestamps and with the verification state. A third-party validator using the schema files alone will not catch that second layer; the schemas document it, this validator enforces it.

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

## Examples

The authored examples are synthetic — every identifier, amount and timestamp is fabricated. The captured example is real product output from the deterministic demo environment, which generates its own payments, tickets and refunds per run; nothing anywhere comes from a real customer, a real payment system, or real operational data.

- [`examples/captured/`](examples/captured/) — a packet composed from the two API responses of a live demo run with `npm run compose`: the conformance proof that real product output fits this schema. See [`docs/CONFORMANCE.md`](docs/CONFORMANCE.md).

- [`examples/valid/`](examples/valid/) — one packet per verification path: [verified](examples/valid/verified-refund.packet.json), [outcome mismatch with a recorded human review decision](examples/valid/outcome-mismatch-decided.packet.json), [technical verification failure](examples/valid/verification-failed.packet.json), and [verification still pending](examples/valid/verification-pending.packet.json).
- [`examples/invalid/`](examples/invalid/) — ten packets, each broken by exactly one documented defect (a fabricated outcome on a mismatch, an evidence item claiming a trust level its type cannot carry, a fabricated zero where "no amount" belongs, and so on). See [`examples/invalid/README.md`](examples/invalid/README.md).

## What successful validation proves — and what it does not

Successful validation proves **conformance to the published packet format, and nothing more**: the document has the declared fields, types, enum values and internal consistency rules of the Public Evidence Packet format.

It does **not** prove:

- **Origin** — that the packet was produced by Pruvz rather than authored by hand.
- **Business accuracy** — that the recorded observations match what actually happened in any real system.
- **Cryptographic integrity or non-tampering** — that the packet was not modified after it was produced.

Packet format v1.0.0 deliberately contains no content hashes, no signed manifests, no hash chaining and no external anchoring, because the current product demonstration does not implement them — and this repository does not claim otherwise. Inside the product, evidence integrity rests on append-only, atomically-sequenced, server-assigned-trust storage; those properties belong to the running system and cannot be established after the fact from a JSON file alone.

## Related material

- [Product demo](https://pruvz.ai/demo) — the end-to-end verification flow this contract is exported from.
- [Security architecture](https://pruvz.ai/security) — trust model, data access, and verification lifecycle.
- [A real captured packet, explained field by field](https://pruvz.ai/evidence-packet) — the captured packet from [`examples/captured/`](examples/captured/) published with its full technical walkthrough: every field group, the evidence timeline, and the verification sequence on the packet's own timestamps.

## License, contributing, security

- Licensed under the [MIT License](LICENSE).
- Contributions and release process: [`CONTRIBUTING.md`](CONTRIBUTING.md). Format changes follow the product — see [`docs/VERSIONING.md`](docs/VERSIONING.md).
- Reporting a vulnerability or a sensitive-data concern: [`SECURITY.md`](SECURITY.md).
