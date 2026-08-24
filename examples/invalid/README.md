# Invalid examples

Each file here is a full packet broken by **exactly one** documented defect, so the automated tests can prove it fails structural validation for that reason and not by accident. The test manifest in [`test/validator.test.mjs`](../../test/validator.test.mjs) asserts the reported error actually matches the defect.

| File | The one defect | What it demonstrates |
|---|---|---|
| `wrong-trust-level.packet.json` | A `SOURCE_READBACK` evidence item claims `trustLevel: "CLAIMED"`. | Trust levels are server-derived from the evidence type; the mapping is part of the contract and the schema enforces it. |
| `fabricated-final-outcome.packet.json` | An `OUTCOME_MISMATCH` action carries `finalOutcome: "REFUND_SUCCEEDED"`. | A mismatch proved nothing — the format cannot express a fabricated business outcome next to a mismatch ruling. |
| `missing-policy-snapshot.packet.json` | The action has no `policySnapshot`. | The immutable decision-time snapshot is part of the action record, always present. |
| `negative-amount.packet.json` | `decision.amount.amount` is `-42.5`. | Monetary amounts are never negative. |
| `undeclared-content-hash.packet.json` | The action carries an undeclared `contentHash` field. | The v1.0.0 format declares no content hash (the product demonstration implements none), and undeclared fields are rejected — a packet cannot smuggle in integrity claims the format does not make. |
| `malformed-timestamp.packet.json` | `createdAtUtc` is `"10/07/2026 09:14"`. | Timestamps must be RFC 3339 / ISO 8601 UTC strings. |
| `offset-timestamp.packet.json` | `updatedAtUtc` is `"2026-07-10T12:15:45+03:00"`. | Fields named `*AtUtc` require the `Z` UTC designator; a local-offset timestamp does not conform even though it is valid RFC 3339. |
| `mismatch-without-dimensions.packet.json` | An `OUTCOME_MISMATCH` action has `mismatch: null`. | A mismatch ruling always carries its expected-versus-observed dimensions. |
| `fabricated-zero-discrepancy.packet.json` | `businessDiscrepancy` has `evaluable: false` with an amount of `0`. | "No amount" is never rendered as a zero — a non-evaluable discrepancy carries no amount at all. |
| `unsupported-format-version.packet.json` | `packetFormatVersion` is `"0.9.0"`. | A packet must declare a format release this schema set defines. |
| `independently-confirmed-not-verified.packet.json` | An `OUTCOME_MISMATCH` action carries `review.independentlyConfirmed: true`. | Independent confirmation exists only when Pruvz's own re-verification proved the resolution — a VERIFIED action with a DECIDED review (format 1.3.0); a non-verified action can never claim it. |
