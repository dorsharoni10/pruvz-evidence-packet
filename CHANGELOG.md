# Changelog

All notable changes to the Public Evidence Packet format and this repository are recorded here. Format releases follow the policy in [`docs/VERSIONING.md`](docs/VERSIONING.md).

## 1.0.0 — 2026-08-02

Initial public release of the Public Evidence Packet format.

- `schema/v1.0.0/` — the packet envelope, the action record, and the ordered evidence timeline, mirroring the action details and evidence views of the Pruvz product API. Timestamps require the `Z` UTC designator, matching the `*AtUtc` field names.
- Structural rules enforced beyond field shapes: terminal-status consistency (a `VERIFIED` action carries a final outcome and nothing else; a mismatch carries its dimensions and no fabricated outcome; a technical failure carries its failure block and no business result; a pending action carries nothing terminal), the server-assigned evidence type-to-trust mapping, and the no-fabricated-zero rule for non-evaluable discrepancies.
- Packet-level consistency validation for the cross-object rules JSON Schema cannot express: matching `actionId` between the two parts, unique/ascending/contiguous timeline sequences, unique evidence ids, `DECIDED` ⇔ `HUMAN_REVIEW_DECISION` coupling, and execution-state/timestamp/verification-state agreement.
- Four synthetic valid examples (verified, mismatch with a recorded human review decision, technical verification failure, verification pending) and ten synthetic invalid examples, each with exactly one documented defect.
- Local validator (`npm run validate -- <file>`), packet composer bridging the two saved API responses of a live run into a conforming packet (`npm run compose`, see `docs/CONFORMANCE.md`), and automated tests (`npm test`).
- A captured conformance proof: a packet composed from the two API responses of a real demo run (2026-08-01), validated by the same tests and CI as the authored examples.
