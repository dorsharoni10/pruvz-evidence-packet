# Field and enum reference — packet format v1.0.0

Every field of the Public Evidence Packet, what it means, and every closed enum value. The authoritative structural rules are the schemas themselves; this document explains intent and semantics.

## Envelope

| Field | Meaning |
|---|---|
| `packetFormatVersion` | The packet format release this document conforms to. Fixed to `"1.0.0"` in this release. Metadata of the file, not a product field. |
| `action` | The action record — see below. |
| `evidence` | The ordered evidence timeline — see below. |

**Enforced by the validator, not expressible in JSON Schema:** `action.actionId` must equal `evidence.actionId`; timeline sequences are unique, ascending and contiguous from 1; evidence ids are unique; a `DECIDED` review state and `HUMAN_REVIEW_DECISION` evidence imply each other; execution state agrees with its timestamps and with the verification state. The bundled validator checks all of these after schema validation — a third-party validator using the schema files alone will not.

## The action record

### Identity and business context

| Field | Meaning |
|---|---|
| `actionId` | Server-generated identifier of the business action. |
| `agentId` | The agent that requested the action. |
| `runId` | The run this action belongs to. |
| `correlationId` | The business correlation key — e.g. the payment the refund belongs to. |
| `actionType` | The kind of business action. The current demonstration exports `refund`. |
| `subject` | The business entity acted on: `subjectType` (e.g. `payment`) and `subjectId`. |
| `decision` | What the policy evaluation approved: `decisionType` (e.g. `REFUND_APPROVED`) and the **decision** amount — never a verified amount. |
| `crmTicketId` | The CRM ticket the decision context referenced; `null` when none was asserted. |

### The three value groups a reviewer compares

These are deliberately separate, so an unverified assertion can never masquerade as an observation:

| Field | Meaning |
|---|---|
| `expectedOutcome` | Derived **server-side** by Pruvz from the decision and the immutable Policy Snapshot. Never accepted as an agent input. `outcomeType` in the current demonstration: `REFUND_SUCCEEDED`. |
| `claim` | The agent's own unverified assertion about its execution (`claimedOutcome`, `claimedAtUtc`). A claim never decides a verification result. |
| `observed` | What independent system-of-record read-back actually observed — the latest `INDEPENDENT_READBACK` evidence, summarized. `null` means no independent observation was recorded yet, reported honestly instead of echoing the claim or the expectation. Its field names match the evidence timeline items so the block can be correlated with its timeline entry. |

### The two state machines

Execution and verification are separate by design: execution reflects what the agent reports, verification reflects what Pruvz proves.

`executionStatus` — agent execution progress:

| Value | Meaning |
|---|---|
| `RECEIVED` | The action was captured. |
| `EXECUTING` | The agent reported execution in progress. |
| `COMPLETED` | The agent reported execution complete; this is what creates the verification job. |

`verificationStatus` — independent verification state. Terminal results are assigned only after independent system-of-record read-back, never through any agent-facing contract:

| Value | Meaning |
|---|---|
| `NOT_STARTED` | No verification job exists yet. |
| `VERIFICATION_PENDING` | Verification is scheduled or in progress; nothing was proven or disproven yet. Unreadable or non-terminal observations keep an action here — they are never misclassified as business mismatches. |
| `VERIFIED` | Independent read-back confirmed the expected business outcome. |
| `OUTCOME_MISMATCH` | Independent read-back observed a terminal state that contradicts the expectation — a business exception. |
| `VERIFICATION_FAILED` | The source could not be read within the bounded retry budget — a **technical** outcome, never a business mismatch. |

A verification result states what the systems of record showed during the verification window. It becomes final on a terminal observation and is not silently re-checked afterward.

### Terminal-result fields

| Field | Meaning |
|---|---|
| `finalOutcome` | The proven business outcome (e.g. `REFUND_SUCCEEDED`). Present **exactly** when `verificationStatus` is `VERIFIED`. A mismatch or technical failure never fabricates one. |
| `verificationFailure` | Present exactly for `VERIFICATION_FAILED`: the Worker's `reason`, the bounded `attemptCount`, and `retryable` — the server's ruling-time verdict on whether a retry could change the result. A technical description, never a business result. |
| `mismatch` | Present exactly for `OUTCOME_MISMATCH` — see below. |
| `verificationCompletedAtUtc` | When the terminal result was assigned; `null` while verification has not concluded. |

### The mismatch block

The review classification and expected-versus-observed dimensions behind one `OUTCOME_MISMATCH` ruling. The observed side is stated as recorded business facts (refund counts, ticket statuses), never as source payload contents.

| Field | Meaning |
|---|---|
| `reasonCode` | Stable machine classification. **Intentionally an open string**: consumers must treat unknown future codes as valid and fall back to `explanation`. Known v1.0.0 codes below. |
| `severity` | `HIGH` or `MEDIUM`, derived from documented rules per reason code. |
| `explanation` | Human-readable statement of the business difference, referencing the observations the classifier used. |
| `expectedOutcomeType`, `expectedAmount` | The server-derived expectation the observation was evaluated against. |
| `observedRefundCount` | Every refund the billing read-back correlated to the payment. |
| `observedQualifyingRefundCount` | Succeeded refunds matching payment, amount and currency. A mismatch observes zero or more than one. |
| `assertedTicketStatus` / `observedTicketStatus` | The decision-time asserted CRM ticket status versus what CRM read-back observed; `null` when not applicable. |
| `businessDiscrepancy` | The mismatch's monetary discrepancy, or its explicit absence. |

Known v1.0.0 `reasonCode` values:

| Code | Meaning | Severity |
|---|---|---|
| `NO_QUALIFYING_REFUND` | The expected refund was not found in the system of record. | `HIGH` |
| `MULTIPLE_QUALIFYING_REFUNDS` | More than one qualifying refund was found — an over-refund. | `HIGH` |
| `CRM_STATE_INCONSISTENT` | The refund may be correct, but the CRM state contradicts what was asserted — a governance exception. | `MEDIUM` |

`businessDiscrepancy` semantics: when `evaluable` is `true`, `amount` carries the server-derived monetary discrepancy. When `evaluable` is `false`, `amount` is `null` — **an unknown discrepancy is never rendered as a zero**, because "no amount" and "zero amount" are different business statements. The schema enforces both directions.

### Review state

`reviewState` — whether the action needs, awaits, or received a human review decision. Only a terminal verification result determines it:

| Value | Meaning |
|---|---|
| `NOT_DETERMINED` | Verification has not concluded; the need for review is honestly unknown — never a terminal-sounding "not required" that would flip later. |
| `PENDING_REVIEW` | An `OUTCOME_MISMATCH` awaits a human ruling. |
| `DECIDED` | The mismatch received its recorded human decision (visible as `HUMAN_REVIEW_DECISION` evidence on the timeline). |
| `NOT_REQUIRED` | `VERIFIED` and `VERIFICATION_FAILED` need no business ruling — a failure proved nothing either way. |

A human review decision is **appended as new ordered evidence**; it never rewrites the original verification result or the mismatch evidence.

### The Policy Snapshot

The complete immutable decision-time snapshot embedded with the action — read from stored state, never re-evaluated on read:

| Field | Meaning |
|---|---|
| `policyId`, `policyVersion` | Which policy, at which version, applied at decision time. |
| `rules` | The rules that applied: `maxPurchaseAgeDays`, `maxRefundAmount`, `allowedPaymentStates`, and the `ticket` requirement (`ticketRequired`, `allowedTicketStatuses`). |
| `input` | The normalized inputs the evaluation saw: `purchasedAtUtc`, `evaluatedAtUtc`, `refundAmount`, `paymentState`, `ticketStatus` (`null` when no ticket was asserted). |
| `evaluation` | The explainable result: `policyPassed` plus one `{ruleId, passed, explanation}` per rule, in policy order. |

### Timestamps

All timestamps are UTC, RFC 3339 / ISO 8601 strings with the `Z` UTC designator (`2026-07-10T09:15:45Z`), enforced by the schema — a local-offset form such as `+03:00` does not conform. `executionStartedAtUtc` and `executionCompletedAtUtc` are `null` until the corresponding transition happened; `executionStartedAtUtc` can remain `null` on a `COMPLETED` action when the agent reported completion without ever reporting an execution start.

## The evidence timeline

`evidence.actionId` — the action the timeline belongs to. `evidence.items` — every timeline entry in sequence order.

Each item:

| Field | Meaning |
|---|---|
| `evidenceId` | Identifier of the evidence item. |
| `sequence` | Position on the action's timeline; allocated atomically, starting at 1. |
| `type` | What kind of event this is — closed enum below. |
| `trustLevel` | How much independent trust the item carries. **Always server-assigned, derived from the type** — never a caller input. The schema enforces the full mapping. |
| `source` | The system the evidence came from — an agent identifier, a source-system identifier, or a Pruvz component identifier. |
| `sourceReference` | An identifier inside the source (e.g. a refund or ticket id); `null` when none applies. |
| `occurredAtUtc` | When the event occurred or was observed. Agent-asserted for claims. |
| `recordedAtUtc` | Server time Pruvz recorded the evidence. |
| `summary` | Business-readable one-line summary. |

Evidence type → trust level (the schema enforces every row):

| `type` | Meaning | `trustLevel` |
|---|---|---|
| `ACTION_REQUEST` | The agent's original action submission. | `CLAIMED` |
| `POLICY_SNAPSHOT_CAPTURE` | Pruvz captured the decision-time Policy Snapshot. | `PRUVZ_DERIVED` |
| `AGENT_CLAIM` | The agent's claim about its execution outcome. | `CLAIMED` |
| `EXECUTION_RECEIPT` | A receipt the agent relayed from the system it executed against. | `EXECUTION_RECEIPT` |
| `SOURCE_READBACK` | Pruvz independently read the system of record. | `INDEPENDENT_READBACK` |
| `VERIFICATION_RETRY` | A user-requested verification retry was recorded and re-armed verification. | `PRUVZ_DERIVED` |
| `VERIFICATION_RESULT` | Pruvz assigned the final verification result. | `PRUVZ_DERIVED` |
| `HUMAN_REVIEW_DECISION` | A human reviewer's documented decision on a mismatch exception, recorded by Pruvz through the controlled review path. | `PRUVZ_DERIVED` |

Trust levels — four provenance classes. `CLAIMED`, `EXECUTION_RECEIPT` and `INDEPENDENT_READBACK` grade how independent a **source observation** is, from least to most; `PRUVZ_DERIVED` marks Pruvz's own derived records (snapshots, rulings, recorded decisions) — a conclusion class, not a more-independent observation:

| Value | Meaning |
|---|---|
| `CLAIMED` | Asserted by the agent; carries no independent trust. |
| `EXECUTION_RECEIPT` | A receipt relayed by the agent from the executing system. |
| `INDEPENDENT_READBACK` | Observed by Pruvz directly from the system of record. Only internal Pruvz paths can create this — no external caller can. |
| `PRUVZ_DERIVED` | Derived by Pruvz itself (snapshots, rulings, recorded decisions). Internal-only, like `INDEPENDENT_READBACK`. |

## Money

Every monetary value is `{ "amount": <non-negative number>, "currency": "<three-letter uppercase ISO 4217 code>" }`. Whether an amount is a decision amount, an expected amount, or a discrepancy is determined by where it appears — the packet never mixes them.
