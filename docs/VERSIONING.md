# Versioning and compatibility policy

The Public Evidence Packet format is versioned independently of the Pruvz product, using semantic versioning: `MAJOR.MINOR.PATCH`. The current release is **1.5.1**.

## What each part means

- **MAJOR** — a breaking change to the packet structure: removing or renaming a field, changing a field's type or nullability, removing an enum value, or tightening a constraint so that previously conforming packets no longer conform.
- **MINOR** — an additive, non-breaking change to what the product exports: a new field, a new evidence type, a new closed-enum value, or a conditional rule relaxed so that a field may now carry values it could not before (for example `1.2.0` admitting review states on a `VERIFICATION_FAILED` action). Packets of format `1.2.0` are **not** guaranteed to validate against the `1.1.0` or `1.0.0` schema (the schemas are strict: undeclared fields are rejected). Compatibility is defined at the consumer level, below.
- **PATCH** — a repository release (documentation, examples, validator or test changes) that does not alter what conforms. Packet documents keep declaring the `MAJOR.MINOR.0` format version of their structure: a documentation-only release `v1.0.1` of this repository changes nothing about packets, which continue to declare `packetFormatVersion: "1.0.0"`.

## Rules consumers can rely on

1. **Validate against the release that matches the packet.** Every packet declares its format in `packetFormatVersion`; every schema release pins that declaration with a `const`. The bundled validator picks the matching schema release automatically.
2. **Released schema directories are immutable — fully.** Once `schema/v1.0.0/` is released, no file in it changes, not even `description` text. Corrections and clarifications go into the documentation under `docs/`, or into the next format version's directory.
3. **Within a MAJOR version, fields never disappear or change meaning.** Code written to read a `1.x` packet keeps working on every later `1.y ≥ 1.x` packet if it ignores fields it does not recognize.
4. **Two fields are open by contract**, and consumers must treat unknown values as valid there: `mismatch.reasonCode` (fall back to `explanation`) and free-form business strings such as `actionType`, `decisionType`, `finalOutcome` and outcome types. Everything declared as a closed enum in the schema (statuses, review states, evidence types, trust levels, severity) only widens with a MINOR release and only narrows with a MAJOR release.
5. **The schema follows the product, never the reverse.** A field appears in this contract only after the product actually exports it, in the same release cycle in which the product's conformance guard proves the export. Roadmap capabilities (for example signed manifests or external anchors) enter the schema only when they are really implemented — never speculatively.
6. **The trust-registry specification is versioned separately from the packet format.** [`docs/TRUST-REGISTRY.md`](TRUST-REGISTRY.md) and `trust-registry/vN/` define how a signing key is published, rotated, revoked and recognized. That directory is immutable exactly like a released schema directory: changing the rules means a new trust-registry format version, never an edit in place. It is independent of both the packet format and the commitment version, and a packet carries no trust-registry material of any kind.
7. **The commitment specification is versioned separately from the packet format.** [`docs/COMMITMENT.md`](COMMITMENT.md) and `commitment/vN/` define how a record is turned into deterministic bytes and a digest. That directory is immutable exactly like a released schema directory: changing the rules means a new commitment version, never an edit in place. A packet format release and a commitment version release are independent — `1.4.0` carries the exact values a commitment needs, and carries no commitment itself.

## Release process

1. The product change ships and its export contract is confirmed (contract tests in the product repositories; see [`CONFORMANCE.md`](CONFORMANCE.md)).
2. For a MAJOR or MINOR format change, a new `schema/vX.Y.0/` directory is added with `packetFormatVersion` pinned to the new format version, and examples plus the validator's supported-version list are updated. A PATCH release touches documentation and tooling only — never a released schema directory.
3. `npm test` must pass.
4. The change is recorded in [`CHANGELOG.md`](../CHANGELOG.md) with its compatibility classification (MAJOR / MINOR / PATCH).
5. The repository is tagged `vX.Y.Z`. **Published tags are permanent: a tag is never moved, deleted or reused.** A fix after tagging is always a new, higher tag.
6. **npm distribution (resolved PRUVZ-97 decision).** The Node CLI and library are additionally published to npm as `@pruvz/evidence-packet`; the public Git repository remains cloneable and authoritative. The package version is identical to the repository release and the git tag — one stream, already independent of `packetFormatVersion`, so a verifier bug fix is a repository PATCH release and never implies a format change. Every npm release is built from the immutable reviewed tag and published with 2FA and npm provenance through [`release.yml`](../.github/workflows/release.yml), as a deliberate post-review step — never automatically on merge. A published registry artifact is effectively irreversible, which is exactly why only the tagged, reviewed bytes ever reach it. The .NET and Python conformance verifiers stay repository/CI-only (no NuGet, no PyPI).
