# Changelog

All notable changes to the Public Evidence Packet format and this repository are recorded here. Format releases follow the policy in [`docs/VERSIONING.md`](docs/VERSIONING.md).

## 1.3.0 — 2026-08-24

**MINOR** — additive human-triggered re-verification fields (product PRUVZ-51, Customer #1 re-verification after `RESOLVED_EXTERNALLY` with fact supersession). Consumers reading `1.2.0` packets keep working on `1.3.0` packets if they ignore fields they do not recognize and treat the closed enums as open to widening; `1.3.0` packets do not validate against the `1.2.0` schema (the schemas are strict by design).

- `schema/v1.3.0/` — new format release:
  - `evidence.items[].type` gains `FOLLOW_UP_INDEPENDENT_READBACK` (trust `INDEPENDENT_READBACK`): an independent read-back performed during a human-triggered re-verification, after a `RESOLVED_EXTERNALLY` review event.
  - `action.reverificationTiming` (new, nullable object, same shape as `verificationTiming`): the fresh verification window of the latest re-verification, resolved through the same precedence chain but anchored to the moment the correction was reported. Null while no `RESOLVED_EXTERNALLY` event ever triggered one; required (non-null) while `reviewState` is `AWAITING_REVERIFICATION`. `verificationTiming` stays the immutable record of the original window.
  - `action.review.independentlyConfirmed` (new, required boolean): true exactly when Pruvz's own re-verification confirmed the externally-reported resolution and closed the review — the packet's human-resolved versus independently-confirmed-resolved distinction.
  - A `VERIFIED` action may now carry `reviewState: "DECIDED"` and a review block with `independentlyConfirmed: true` (a confirmed external resolution); a first-pass `VERIFIED` still auto-clears to `NOT_REQUIRED` with a null review. No human decision produces `VERIFIED` — only Pruvz's re-verification can.
  - The terminal status taxonomy, review decision vocabulary and trust levels are unchanged.
- New packet-level consistency rules for `1.3.0`: the Worker's re-verification transitions are the only legal gaps in the review-state chain — after a `RESOLVED_EXTERNALLY` decision the review may sit at `DECIDED` (action `VERIFIED`, independently confirmed) or return to `PENDING_REVIEW` (a new non-verified ruling) without a decision entry; `FOLLOW_UP_INDEPENDENT_READBACK` evidence requires a `RESOLVED_EXTERNALLY` decision in the review history and a recorded `reverificationTiming`; a recorded (non-null) `reverificationTiming` itself requires a `RESOLVED_EXTERNALLY` decision — only that event opens a fresh window; `independentlyConfirmed: true` and a review on a `VERIFIED` action both require the latest decision to be `RESOLVED_EXTERNALLY`. Packets of formats `1.2.0` and earlier keep their strict chain rules.
- The five synthetic valid examples now declare format `1.3.0` and carry the new fields; two new examples show the re-verification outcomes: `reverified-confirmed.packet.json` (mismatch → correction reported → follow-up read-back → `VERIFIED`, review `DECIDED`, independently confirmed) and `reverified-mismatch.packet.json` (the reported correction never appeared → `OUTCOME_MISMATCH` again, review back to `PENDING_REVIEW`). A new invalid example, `independently-confirmed-not-verified.packet.json`, shows the marker rejected on a non-verified action. The captured `1.0.0` conformance proof is unchanged. The validator supports all four formats and picks the release matching each packet's declaration.

## 1.2.0 — 2026-08-23

**MINOR** — additive human-review lifecycle fields (product PRUVZ-49, Customer #1 review lifecycle). Consumers reading `1.1.0` packets keep working on `1.2.0` packets if they ignore fields they do not recognize and treat the closed enums as open to widening; `1.2.0` packets do not validate against the `1.1.0` schema (the schemas are strict by design).

- `schema/v1.2.0/` — new format release:
  - `action.reviewState` gains `NEEDS_CORRECTION` and `AWAITING_REVERIFICATION`. A `VERIFICATION_FAILED` action is now under review — it reports a workflow state (`PENDING_REVIEW` first) instead of `NOT_REQUIRED`; `VERIFIED` still auto-clears to `NOT_REQUIRED`.
  - `action.review` (new, nullable object): present exactly for `OUTCOME_MISMATCH` and `VERIFICATION_FAILED` — the review `category` (`BUSINESS_MISMATCH` or `VERIFICATION_FAILURE`, derived from the terminal result), the current `latestDecision` (or `null`) and the complete `decisions` history, one entry per `HUMAN_REVIEW_DECISION` timeline item: `decision` (`APPROVED_EXCEPTION`, `DISMISSED`, `NEEDS_CORRECTION`, `RESOLVED_EXTERNALLY`), `reason`, `reviewerId`, `previousReviewState`, `newReviewState`, the reviewed evidence reference, the decision's own `evidenceId`/`evidenceSequence` and `decidedAtUtc`.
  - The locked review transitions and the category × decision rule (a `VERIFICATION_FAILURE` never admits `APPROVED_EXCEPTION`) are documented in `docs/FIELDS.md`; no review decision can produce `VERIFIED`.
  - The terminal status taxonomy, evidence types and trust levels are unchanged.
- New packet-level consistency rules for `1.2.0`: `review.decisions` lists exactly the timeline's `HUMAN_REVIEW_DECISION` items, in order, each decision's `previousReviewState` continues the previous one's `newReviewState` from `PENDING_REVIEW`; `latestDecision` is the last entry or `null`; `reviewState` equals the latest decision's `newReviewState`, or `PENDING_REVIEW` while no decision was recorded; a `null` review admits no decision evidence. The `1.0.0`/`1.1.0` rule (`DECIDED` ⇔ `HUMAN_REVIEW_DECISION` evidence) still applies to packets of those formats.
- The four synthetic valid examples now declare format `1.2.0` and carry the review block; a fifth example, `verification-failed-resolved-externally.packet.json`, shows a failure review driven through `NEEDS_CORRECTION` and `RESOLVED_EXTERNALLY`. The captured `1.0.0` conformance proof is unchanged. The validator supports all three formats (`1.2.0`, `1.1.0`, `1.0.0`) and picks the release matching each packet's declaration.

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
