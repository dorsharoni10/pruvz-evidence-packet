# Changelog

All notable changes to the Public Evidence Packet format and this repository are recorded here. Format releases follow the policy in [`docs/VERSIONING.md`](docs/VERSIONING.md).

## 1.1.0 — 2026-08-17

**MINOR** — additive temporal-verification fields (product PRUVZ-84). Consumers reading `1.0.0` packets keep working on `1.1.0` packets if they ignore fields they do not recognize; `1.1.0` packets do not validate against the `1.0.0` schema (the schemas are strict by design).

- `schema/v1.1.0/` — new format release:
  - `action.verificationTiming` (new, nullable object): the action's frozen verification timing, resolved exactly once at acceptance and never re-resolved — `initialCheckAfterSeconds`, `readbackIntervalSeconds`, `deadlineAtUtc` (null when no deadline was resolved; such an action can never produce a time-based mismatch), `deadlineSource` (`POLICY` → `TENANT_OVERRIDE` → `PRODUCT_SPEC` → `NOT_CONFIGURED`, in resolution precedence order) and `resolvedAtUtc`. Null only on action records that predate the timing model.
  - `action.mismatch.mismatchReason` (new, required in the mismatch block): the temporal mismatch category — `CONTRADICTORY_EVIDENCE` (positive evidence contradicts the claim; assigned immediately) or `EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE` (the expected outcome never appeared and the resolved deadline passed).
  - `action.policySnapshot.rules.verificationDeadlineSeconds` (new, nullable): the policy's verification deadline, so a `POLICY`-sourced timing resolution is explainable from the packet.
  - `mismatch.reasonCode` known codes gain `REFUND_FAILED` (a matching refund observed in a terminal failed state — contradictory evidence). The field remains an open string by contract.
  - The terminal status taxonomy, review states, evidence types and trust levels are unchanged.
- New packet-level consistency rule: `EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE` requires a resolved `verificationTiming.deadlineAtUtc`.
- The four synthetic valid examples now declare format `1.1.0` and carry the new fields; the captured `1.0.0` conformance proof is unchanged. The validator supports both formats (`1.1.0`, `1.0.0`) and picks the release matching each packet's declaration.

## 1.0.0 — 2026-08-02

Initial public release of the Public Evidence Packet format.

- `schema/v1.0.0/` — the packet envelope, the action record, and the ordered evidence timeline, mirroring the action details and evidence views of the Pruvz product API. Timestamps require the `Z` UTC designator, matching the `*AtUtc` field names.
- Structural rules enforced beyond field shapes: terminal-status consistency (a `VERIFIED` action carries a final outcome and nothing else; a mismatch carries its dimensions and no fabricated outcome; a technical failure carries its failure block and no business result; a pending action carries nothing terminal), the server-assigned evidence type-to-trust mapping, and the no-fabricated-zero rule for non-evaluable discrepancies.
- Packet-level consistency validation for the cross-object rules JSON Schema cannot express: matching `actionId` between the two parts, unique/ascending/contiguous timeline sequences, unique evidence ids, `DECIDED` ⇔ `HUMAN_REVIEW_DECISION` coupling, and execution-state/timestamp/verification-state agreement.
- Four synthetic valid examples (verified, mismatch with a recorded human review decision, technical verification failure, verification pending) and ten synthetic invalid examples, each with exactly one documented defect.
- Local validator (`npm run validate -- <file>`), packet composer bridging the two saved API responses of a live run into a conforming packet (`npm run compose`, see `docs/CONFORMANCE.md`), and automated tests (`npm test`).
- A captured conformance proof: a packet composed from the two API responses of a real demo run (2026-08-01), validated by the same tests and CI as the authored examples.
