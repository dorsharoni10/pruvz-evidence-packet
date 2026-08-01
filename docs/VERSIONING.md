# Versioning and compatibility policy

The Public Evidence Packet format is versioned independently of the Pruvz product, using semantic versioning: `MAJOR.MINOR.PATCH`. The current release is **1.0.0**.

## What each part means

- **MAJOR** — a breaking change to the packet structure: removing or renaming a field, changing a field's type or nullability, removing an enum value, or tightening a constraint so that previously conforming packets no longer conform.
- **MINOR** — an additive, non-breaking change to what the product exports: a new field, a new evidence type, a new closed-enum value. Packets of format `1.1.0` are **not** guaranteed to validate against the `1.0.0` schema (the schemas are strict: undeclared fields are rejected). Compatibility is defined at the consumer level, below.
- **PATCH** — a repository release (documentation, examples, validator or test changes) that does not alter what conforms. Packet documents keep declaring the `MAJOR.MINOR.0` format version of their structure: a documentation-only release `v1.0.1` of this repository changes nothing about packets, which continue to declare `packetFormatVersion: "1.0.0"`.

## Rules consumers can rely on

1. **Validate against the release that matches the packet.** Every packet declares its format in `packetFormatVersion`; every schema release pins that declaration with a `const`. The bundled validator picks the matching schema release automatically.
2. **Released schema directories are immutable — fully.** Once `schema/v1.0.0/` is released, no file in it changes, not even `description` text. Corrections and clarifications go into the documentation under `docs/`, or into the next format version's directory.
3. **Within a MAJOR version, fields never disappear or change meaning.** Code written to read a `1.x` packet keeps working on every later `1.y ≥ 1.x` packet if it ignores fields it does not recognize.
4. **Two fields are open by contract**, and consumers must treat unknown values as valid there: `mismatch.reasonCode` (fall back to `explanation`) and free-form business strings such as `actionType`, `decisionType`, `finalOutcome` and outcome types. Everything declared as a closed enum in the schema (statuses, review states, evidence types, trust levels, severity) only widens with a MINOR release and only narrows with a MAJOR release.
5. **The schema follows the product, never the reverse.** A field appears in this contract only after the product demonstration actually exports it. Roadmap capabilities (for example content hashing or signed manifests) enter the schema only when they are really implemented — never speculatively.

## Release process

1. The product change ships and its export contract is confirmed (contract tests in the product repositories; see [`CONFORMANCE.md`](CONFORMANCE.md)).
2. For a MAJOR or MINOR format change, a new `schema/vX.Y.0/` directory is added with `packetFormatVersion` pinned to the new format version, and examples plus the validator's supported-version list are updated. A PATCH release touches documentation and tooling only — never a released schema directory.
3. `npm test` must pass.
4. The change is recorded in [`CHANGELOG.md`](../CHANGELOG.md) with its compatibility classification (MAJOR / MINOR / PATCH).
5. The repository is tagged `vX.Y.Z`. **Published tags are permanent: a tag is never moved, deleted or reused.** A fix after tagging is always a new, higher tag.
