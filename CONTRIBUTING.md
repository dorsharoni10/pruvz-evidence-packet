# Contributing

Thanks for looking under the hood. Issues and pull requests are welcome, with one structural rule to be aware of up front.

## The schema follows the product

This repository publishes the export contract of the Pruvz product demonstration. The schema can only describe what the product actually exports, so:

- **Contract changes** (new fields, new enum values, changed shapes) originate in the product, not here. If you need the packet to carry something it does not, open an issue describing the use case — that is genuinely useful input — but a pull request adding fields the product does not export will be declined regardless of quality.
- **Everything else is fair game for direct pull requests**: documentation clarity, additional valid/invalid examples, validator ergonomics, test coverage, tooling.

## Ground rules

- Released schema directories (`schema/vX.Y.Z/`) are immutable — see [`docs/VERSIONING.md`](docs/VERSIONING.md). Propose changes as a new version, not as edits to a released one.
- Examples must stay fully synthetic. No real identifiers, no real amounts traceable to a person or account, nothing captured from a live system.
- Every new invalid example needs exactly one documented defect and a matching entry in the test manifest (`test/validator.test.mjs`), so it fails for the right reason.
- `npm test` must pass. CI runs the tests plus the documented validation command on every pull request.

## Releases

Versioned releases follow the process in [`docs/VERSIONING.md`](docs/VERSIONING.md): a schema release is cut only after the corresponding product contract is confirmed, recorded in [`CHANGELOG.md`](CHANGELOG.md), and tagged `vX.Y.Z`.
