# The Independent Offline Verifier, format version 1

How a Pruvz Evidence Packet is verified **without calling the Pruvz application and without trusting its mutable database** — by anyone: a customer, an auditor, a regulator, a security reviewer. The verifier composes every layer this repository publishes — the packet format, the canonical commitment ([`COMMITMENT.md`](COMMITMENT.md)), evidence seals and the trust registry ([`TRUST-REGISTRY.md`](TRUST-REGISTRY.md)), the append-only log ([`EVIDENCE-LOG.md`](EVIDENCE-LOG.md)) and external anchoring, both halves ([`ANCHORING.md`](ANCHORING.md)) — into one dimensional assurance report.

The reference implementation is [`lib/verify.mjs`](../lib/verify.mjs) with the CLI [`bin/verify.mjs`](../bin/verify.mjs) and the bundle composer [`bin/bundle.mjs`](../bin/bundle.mjs); the published cross-runtime cases are [`verifier/v1/golden-vectors.json`](../verifier/v1/golden-vectors.json). Everything runs locally: no network access, no telemetry, no phone-home of any kind.

## 1. The trust model, stated honestly

**One bootstrap is legitimate and unavoidable**: the pinned `{ issuer, root }` trust anchor of [`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §4, obtained out of band. After that bootstrap, nothing depends on the current Pruvz website, API or database being honest:

- The trust-registry chain is **supplied in the bundle and checked against the pin** — never fetched, and never silently replaced by whatever the website serves today.
- Seal, checkpoint and manifest signatures are recomputed from the documents themselves (the signing inputs are rebuilt canonically; transported byte strings are never trusted).
- The commitment digest a seal names is **recomputed from the record**, never read off the envelope — which is why packet format `1.5.0` exposes every commitment-bound item field.
- Anchors are verified against **caller-pinned timestamp-authority roots**, never an ambient trust store.
- With `--state`, the verifier keeps what it accepted, so a rolled-back, forked or substituted history is a refusal on the next run — exactly the held-history rules of the registry and log layers.

**What the verifier can never establish**: that the recorded business facts are true. Cryptography preserves evidence; it does not make incorrect evidence correct. A `FULLY_VERIFIED` verdict means *these are the exact bytes Pruvz committed to, signed by a recognized key that was trustworthy at signing time, included in an append-only history whose head was witnessed outside Pruvz* — nothing more.

## 2. The verification bundle

One JSON document holding everything the producing deployment served, verbatim. A bundle file whose JSON serialization carries a **duplicated member name** — compared on decoded values, so an escape spelling such as `"\u0061"` for `"a"` hides nothing — is unusable input (exit `2`), refused before parsing: RFC 8259 leaves duplicates undefined and real parsers disagree, so one byte string could be two different documents — the reviewer reads the first occurrence while a last-wins parser commits to the second (PRUVZ-97, conformance case `duplicate-member-refused`). The member set is closed:

```jsonc
{
  "bundleFormatVersion": "1",
  "packet": { /* the Public Evidence Packet, or null for a proof-only bundle */ },
  "seals": { "<evidenceId>": { "envelope": {}, "signature": "" } },      // GET .../evidence/{id}/seal
  "proofs": { "<evidenceId>": { "leafIndex": 0, "leafHash": "", "path": [], "checkpoint": {} } }, // GET .../evidence/{id}/proof
  "checkpoints": [ { "checkpoint": {}, "signature": "" } ],              // optional additional history
  "consistencyProofs": [ { "fromSize": 0, "toSize": 0, "proof": [] } ],
  "trustRegistry": [ /* the served registry documents, version order */ ],
  "anchors": {
    "checkpoints": { "<sequence>": { "anchors": [] } },                  // GET .../checkpoints/{seq}/anchors
    "trustRegistry": { "<version>": { "anchors": [] } }                  // GET /api/trust-registry/{v}/anchors
  }
}
```

Every part is optional except `bundleFormatVersion`. Assembling less material produces a **weaker verdict**, never an error: a bundle without anchors verifies everything else and reports the anchors dimension absent. `bin/bundle.mjs` composes this file from a directory of saved responses (its header documents the expected layout and the exact product endpoints).

A **proof-only bundle** (`packet: null`) is the honest shape of a record whose payload retention deleted while the holder kept the export: what survives proves the sealed record existed and is covered by the log — and is reported as `RETAINED_PROOF_ONLY`, never as payload availability.

## 3. The report is dimensional

Collapsing verification into a boolean is how a partially verified record gets reported as a verified one. The report answers each question separately:

| Dimension | Question |
|---|---|
| `packet` | Does the payload conform to its declared packet format (schema + consistency layer)? |
| `commitment` | Does each record hash to the digest its seal names — recomputed from the record itself? |
| `seals` | Signature validity, key identity, key lifecycle **at signing time**, subject binding — per record ([`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §9). |
| `trustRegistry` | Does the supplied key-history chain verify against the pin, link by link, with no rollback or fork? |
| `logInclusion` | Is each seal's leaf at its claimed position of a signed checkpoint's tree? |
| `logConsistency` | Are the bundle's checkpoints — and the held state — connected by append-only consistency proofs? |
| `checkpoints` | Are checkpoints signed by registry-recognized evidence keys that were `ACTIVE` at `issuedAt`? |
| `anchors` | Was the history witnessed outside Pruvz — bindings (half one) *and* authority verification (half two)? |
| `assuranceProfile` | Which locked assurance profile (`PRE_CUSTOMER_DEFAULT` / `CUSTOMER_PRODUCTION`) produced this material, as bound into the signed envelopes — so a lower-cost profile can never be mistaken for a stronger one. |
| `suiteSupport` | Were all formats, versions and crypto suites ones this implementation speaks? |
| `retention` | Payload present, or retained proof only? |

Plus a per-record `evidence` array (commitment / seal / inclusion result for every item) and a flat, machine-readable `reasonCodes` list with human `explanations`. The verifier's own reason codes are the closed `REASON_CODES` list in [`lib/verify.mjs`](../lib/verify.mjs); codes minted by the composed layers flow through verbatim and are documented by their layers.

## 4. The verdict

```text
FULLY_VERIFIED      every dimension verified; nothing absent, nothing weakened
PARTIALLY_VERIFIED  nothing failed, but something could not be checked
NOT_VERIFIED        something checked and failed
```

Three rules, none negotiable:

1. **Missing material weakens; it never passes.** A valid signature with missing required anchor, consistency or trust material is `PARTIALLY_VERIFIED` at best — never `FULLY_VERIFIED`.
2. **Presented material that fails is a refusal, never a downgrade.** A tampered record, an invalid signature, a receipt that does not verify: `NOT_VERIFIED`. The one thing worse than absent proof is failed proof reported as partial.
3. **A cost-gated capability that the producing deployment did not run is reported honestly as absent** (`COST_GATED_CAPABILITY_ABSENT`), weakens the verdict, and can never yield `FULLY_VERIFIED`. Under `PRE_CUSTOMER_DEFAULT`, external anchoring is off by default — so packets from such deployments verify to `PARTIALLY_VERIFIED`, and that is the truthful answer, not a defect.

`FULLY_VERIFIED` is therefore reachable only when the packet is commitment-complete (format `1.5.0` or later), every record is sealed and proven included, the checkpoints chain under the pinned registry, and the covering history was witnessed by an authority the caller pinned. The golden vectors pin this: exactly one published case reaches it.

## 5. Time-aware key semantics

Rotation and revocation follow the registry layer exactly, and the verifier surfaces them rather than flattening them:

- A key retired **after** signing changes nothing (`KEY_RETIRED_AFTER_SIGNING`): historical evidence stays verifiable across normal rotation.
- A seal or checkpoint signed while its key was `NOT_YET_VALID`, `RETIRED` or `REVOKED` is a refusal.
- A signature made **before** a later-declared revocation is weakened (`SIGNED_BEFORE_REVOCATION`, `COMMITTED_AT_SELF_ASSERTED`): the boundary is compared against a time Pruvz itself asserted, and only an external witness of the material settles that — which is precisely what a witnessed anchor adds.

## 6. Anchor verification, both halves

Half one (binding — [`ANCHORING.md`](ANCHORING.md) §6) is checked always. Half two — the CMS signature over the token, the sole and critical timestamping purpose, certificate validity **at the token's own `genTime`**, and a chain ending at a **caller-pinned root** — is implemented in [`lib/anchor-authority.mjs`](../lib/anchor-authority.mjs) (composition of maintained libraries: `node:crypto` and `pkijs`; nothing cryptographic is invented here) and runs when `--tsa-roots` is given. Without pinned roots the anchors dimension honestly reports `BINDING_ONLY` / `ANCHOR_AUTHORITY_NOT_EVALUATED`.

The published `runtimeDivergence` boundary holds at bundle level and is pinned by a golden case: a token with altered signature bytes still binds, and this verifier refuses it (`ANCHOR_SIGNATURE_INVALID`).

## 7. Held state

`--state <file>` names what this verifier accepted before: the registry version and digest, and the newest checkpoint. With it:

- an older registry manifest, a second manifest at a held version, or a broken predecessor link is a refusal (registry rules, [`TRUST-REGISTRY.md`](TRUST-REGISTRY.md) §8);
- two checkpoints that disagree at one sequence — the held state against a bundle, or the same sequence served twice inside one bundle — are `CHECKPOINT_FORK`. Checkpoints are compared as documents, never as byte strings, so the same checkpoint re-serialized in another key order (two endpoints, or a holder who reformatted a saved export) stays one checkpoint;
- only a checkpoint whose signature verified under the pinned registry ever enters the held state: unverifiable material is reported, never remembered. A bundle served without a trust registry is a legitimate `PARTIALLY_VERIFIED` shape, and it must not be able to plant a head that makes every genuine export afterwards look like stale history;
- a bundle whose newest checkpoint is **older** than the held state is treated as what it is: a historical export. It is reported unconnected (`CONSISTENCY_NOT_PROVEN`) and **never regresses the held state** — presenting old history gains an attacker nothing.

State is scoped to the anchor that produced it: state established under one pin is refused under another, and a file that is not exactly what a previous run returned is refused as unusable input (`STATE_MALFORMED`, exit `2`) rather than reinterpreted — reinterpreting it would either accuse genuine evidence of forgery or silently switch the protection off. A first run has nothing to compare against (`STATE_FIRST_USE`, informational); what anchors *that* trust is the out-of-band pin and, where present, the witnessed anchors.

## 8. Running it

```bash
npm ci

# Replay the published golden cases (also runs offline)
npm test

# Compose a bundle from saved responses, then verify
npm run bundle -- ./export-dir verification.bundle.json
npm run verify -- verification.bundle.json --issuer pruvz.ai --root "sha256:<thumbprint>" --tenant <tenantId> --tsa-roots tsa-roots.pem --state verifier-state.json
```

Exit codes: `0` FULLY_VERIFIED · `3` PARTIALLY_VERIFIED · `1` NOT_VERIFIED · `2` unusable input. `--json` prints the full machine-readable report. `--tenant` pins the tenant the caller believes the record belongs to, and it is checked in every bundle shape — a proof-only export included: material sealed for another tenant is `TENANT_MISMATCH`, a refusal. Without it the tenant is taken from the signed envelopes and the report says so (`TENANT_FROM_ENVELOPE`).

No Pruvz account, API key, private key or network connection is required, and the verifier holds no secrets: every input is public-key material and exported documents.

## 9. The golden vectors

[`verifier/v1/golden-vectors.json`](../verifier/v1/golden-vectors.json) publishes complete bundles and the exact expected report for each — verdict, the full reason-code set, and every dimension status. The cases pin the boundaries this format is about: the one reachable `FULLY_VERIFIED`; honest degradation for absent anchors, absent registry, absent payload and unpinned authorities; and refusals for a tampered record, a tampered seal signature, a corrupted receipt and a wrong pin. `verifier/v1/` is immutable exactly like a released schema directory. The adversarial breadth beyond these boundaries is [`docs/CONFORMANCE-SUITE.md`](CONFORMANCE-SUITE.md) (product PRUVZ-97): `conformance/v1/` publishes the attack-matrix cases, and three independent verifiers — this one, .NET and Python — must reproduce every case identically.

**Erratum (recorded under PRUVZ-97, the file itself is immutable):** the `anchor-token-signature-corrupted` case in `verifier/v1` pinned the reason code `ANCHOR_RECEIPT_SIGNATURE_INVALID`, a code outside the anchoring layer's closed vocabulary. The accurate code — the one [`ANCHORING.md`](ANCHORING.md) §10 and the immutable `anchoring/v1` `runtimeDivergence` vector require — is `ANCHOR_SIGNATURE_INVALID`. Every replay of `verifier/v1` substitutes the corrected code for that one case; `conformance/v1` pins the corrected code directly.

## 10. What this format does not do

- It does not prove recorded business facts are true — capture fidelity and post-capture integrity are separate assurance dimensions, deliberately.
- It does not prove `committedAt` or `issuedAt` are exact times; a witnessed anchor proves existence **no later than** the authority's time.
- It does not decide what a court, a regulator or a policy accepts. It states what was cryptographically established, what failed, and what could not be checked — the decision belongs to the reader.
- It never uses the words *tamper-proof*. Tamper-evident, for checkpointed and witnessed history, is what the mathematics supports.

