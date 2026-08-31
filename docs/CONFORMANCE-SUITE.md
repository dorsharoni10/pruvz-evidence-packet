# The adversarial conformance suite, version 1 (PRUVZ-97)

Three independent verifiers — Node, .NET 8 and Python — implement the complete
Evidence Packet proof chain from the published specifications alone, and every
published vector must produce the identical result in all three. This is the
suite that makes the claim "independently verifiable" testable: an
implementation bug cannot masquerade as cryptographic assurance when two other
runtimes, sharing no code with it, must reach the same verdict for the same
reason on the same bytes.

- Adversarial vectors: [`conformance/v1/golden-vectors.json`](../conformance/v1/golden-vectors.json)
- Harnesses: [`conformance/node/`](../conformance/node/), [`conformance/dotnet/`](../conformance/dotnet/), [`conformance/python/`](../conformance/python/)
- The comparison: [`bin/conformance-compare.mjs`](../bin/conformance-compare.mjs)

## 1. The three-runtime rule

Every security layer is verified by every runtime. There is no
"reference-only" tier and no security check that exists in one implementation
only: all three implement canonicalization and commitment digests, ES256
signatures, the trust-registry chain with rotation/revocation/rollback,
Merkle roots with inclusion and consistency proofs, checkpoint acceptance
with stateful fork/stale detection, anchor bindings, **and** RFC 3161 half
two — the CMS signature over the token, the timestamping EKU (critical and
sole), certificate validity at the token's own `genTime`, and the chain to a
caller-pinned root. Each can independently reach `FULLY_VERIFIED`.

Independence is structural, not aspirational:

- The Node verifier is the repository's reference implementation
  (`lib/*.mjs`), whose only cryptographic dependencies are `node:crypto` and
  the pinned `pkijs`/`asn1js` pair.
- The .NET verifier (`conformance/dotnet/`) is implemented from the
  specifications in `docs/` alone, over the platform's maintained surface —
  `ECDsa`, `SignedCms`, `X509Chain`, `System.Formats.Asn1` — plus the pinned
  `JsonSchema.Net`. It uses no code, assemblies or packages from `pruvz-core`.
- The Python verifier (`conformance/python/`) is implemented from the same
  specifications over the maintained `cryptography`, `asn1crypto` and
  `jsonschema` libraries. It never calls the Node or .NET implementations and
  never reads their results.

No runtime may read a vector's expectation to produce its answer. Each
harness computes a normalized results document from vector inputs alone;
`bin/conformance-compare.mjs` is the single place expectations are read, and
it asserts all four equalities: Node == expected, .NET == expected,
Python == expected, and Node == .NET == Python over the **entire** normalized
document — verdicts, sorted reason codes, dimension statuses, canonical
bytes and digests, Merkle roots, and the state a stateful case returns.
Rule one catches an implementation that drifted; rule two catches two
implementations agreeing on the same mistake, and a hidden assumption shared
with the vectors.

## 2. What the adversarial vectors cover

`conformance/v1/golden-vectors.json` publishes 35 signed bundles, three raw
byte strings, and 41 cases mapped to the PRUVZ-97 attack matrix (the
`attackMatrix` index in the file lists which case covers which row):

- **Mutation of committed material** — a signed evidence field edited after
  sealing; a timestamp's *value* changed (refused) versus the same instant
  *respelled* (accepted — normalization is not tampering).
- **Serialization ambiguity** — the baseline re-serialized with reversed
  member order and whitespace yields the identical report; a byte string with
  a **duplicate member name** parses as two different documents and every
  runtime refuses it as unusable input; a truncated export is unusable input,
  never a weaker bundle.
- **Replay** — valid seals swapped across evidence records, and seals
  genuinely made for another tenant or another action.
- **Key substitution and misuse** — a complete internally-consistent registry
  under a different root; a seal by an unpublished key; the trust root
  sealing evidence.
- **Key lifecycle** — rotation preserving history; the back-dated compromise
  boundary weakening what was sealed before it and refusing what was sealed
  at or after it.
- **Registry history (stateful)** — a correctly signed older registry
  presented to a verifier that already accepted a newer one; a genuinely
  signed fork at a held version.
- **Merkle history** — leaf deletion, reordering, and an insider inserting a
  leaf inside checkpointed history under a genuine signature (no consistency
  proof can connect the honest head to it); corrupted inclusion and
  consistency proofs.
- **Checkpoint history (stateful)** — forks inside one bundle and against
  held state, rollback, and stale history that never regresses the held
  state. Every forged checkpoint is genuinely signed by the real evidence
  key: the adversary modeled is a compromised deployment, and only held
  state and consistency rules catch it.
- **Anchors** — a genuine receipt swapped onto another subject, a replayed
  request nonce, the genuine token verified against a different pinned
  authority root, a token whose signature bytes were altered (binds under
  half one, refused by half two — `ANCHOR_SIGNATURE_INVALID` in all three
  runtimes), a pending anchor claimed as a witness, and an anchor whose
  subject carries a tenant identifier (the privacy boundary, refused as
  malformed).
- **Assurance profile** — material genuinely claiming `CUSTOMER_PRODUCTION`
  with no anchors (the upgraded claim the packet cannot prove never reaches
  `FULLY_VERIFIED`); a transported profile mutation breaking the signature;
  mixed profiles reported, never averaged.
- **Truncation and retention** — a shortened timeline whose seal set still
  names the removed record; a proof-only bundle reported as
  `RETAINED_PROOF_ONLY`, never as payload verification.

Stateful cases are multi-step: step one establishes real state (the object a
previous run returned), step two verifies against it — exactly as a CLI
caller threads `--state`. The expected `state` after every step is pinned
and compared.

The four layer packs (`commitment/v1`, `trust-registry/v1`,
`evidence-log/v1`, `anchoring/v1`) and the `verifier/v1` cases are replayed
by all three runtimes as well — byte-identical canonical bytes, digests,
thumbprints, Merkle roots and signing-input hashes, and identical refusal
codes on every negative vector.

`conformance/v1/` is **immutable** exactly like every other released vector
directory. The minting script (`conformance/mint-conformance.mjs`) is
committed for provenance only: ECDSA and the nonces are randomized, so
re-running produces different signed bytes — the published bytes are the
agreement point, and a change to the suite is a new conformance version.

## 3. The harness contract

Each harness emits one JSON document:

```jsonc
{
  "harnessResultsVersion": "1",
  "runtime": "node" | "dotnet" | "python",
  "layers": { "commitment": {...}, "trustRegistry": {...}, "evidenceLog": {...}, "anchoring": {...} },
  "verifierV1":  { "<caseId>": { "outcome", "verdict", "reasonCodes", "dimensions", "state" } },
  "conformance": { "<caseId>": [ /* one entry per step */ ] }
}
```

A step that must be refused before verification (duplicate member, truncated
JSON) is `{ "outcome": "UNUSABLE_INPUT" }`. Reason codes are sorted;
dimensions are the per-dimension status strings; `state` is the exact object
a caller would persist. Running everything locally:

```bash
npm run conformance          # node harness + single-runtime comparison
npm run conformance:all      # all three harnesses + the full three-way comparison
```

(`conformance:all` needs the .NET 8 SDK and a Python 3.12 with
`pip install --require-hashes -r conformance/python/requirements.txt`.)

**Packaged mode (PRUVZ-101).** The same harnesses can run against the built
packages instead of the working tree, which is how CI (`packaged` job) and the
release workflow prove that the published artifacts carry the conformance-gated
behavior. `PRUVZ_CONFORMANCE_PACKAGED=1` makes the Python harness import the
*installed* `pruvz_verifier` (never the working tree, `PRUVZ_SCHEMA_SOURCE=package`
forbidding any schema fallback to the repository), and makes the .NET harness
prove the loaded verifier assembly is byte-identical to the restored NuGet
package (`-p:UsePackagedVerifier=true -p:PackagedVerifierVersion=X.Y.Z`; the
harness's `NuGet.config` source-maps `Pruvz.*` to the built `artifacts/nupkg`
folder only, so a same-versioned package already on nuget.org can never
satisfy the restore — the isolated images pin the same mapping). The isolated
offline acceptance under `conformance/isolated/` then runs both installed CLIs
inside `--network none` containers that contain no repository clone.

## 4. Scope notes, stated honestly

- **Packet schema evaluation** uses a maintained JSON Schema library per
  runtime (Ajv, JsonSchema.Net, `jsonschema`); the packet-level consistency
  rules are implemented independently in each. The conformance bundles carry
  schema-valid packets, so the packet dimension agreeing means the three
  engines agree on real inputs — the schema layer's own negative coverage
  lives in `examples/invalid/` and the validator tests.
- **The `runtimeDivergence` section of `anchoring/v1`** documents the
  boundary between half-one-only implementations and full verifiers. All
  three harnesses here are full verifiers, so on the published
  corrupted-signature token all three refuse with
  `ANCHOR_SIGNATURE_INVALID`; the divergence remains published for
  implementations that stop at half one.
- **A pinned trust anchor may be a non-self-signed certificate** (an
  intermediate the caller chose to pin). The .NET chain builder handles this
  explicitly: when `CustomRootTrust` fails, the chain is rebuilt tolerating
  an unknown authority and trusted only if a pinned certificate is one of
  the built, signature-verified elements with no other defect.

## 5. Dependency provenance and update policy

Cryptographic and schema dependencies are pinned exactly; nothing here
implements a cryptographic primitive.

| Runtime | Package | Pin | Role |
| --- | --- | --- | --- |
| Node | `pkijs` / `asn1js` | `package-lock.json` | CMS/X.509 for anchor half two (PRUVZ-88) |
| Node | `ajv` + `ajv-formats` | `package-lock.json` | JSON Schema 2020-12 |
| .NET | `System.Security.Cryptography.Pkcs` | 10.0.11 (`packages.lock.json`) | `SignedCms` / `Rfc3161` CMS surface (Microsoft) |
| .NET | `JsonSchema.Net` | 9.4.0 (`packages.lock.json`) | JSON Schema 2020-12 |
| Python | `cryptography` | 50.0.1 (hash-pinned) | ECDSA/RSA verification, X.509 parsing (PyCA) |
| Python | `asn1crypto` | 1.5.1 (hash-pinned) | CMS / TSTInfo parsing |
| Python | `jsonschema` (+`referencing`) | 4.26.0 / 0.37.0 (hash-pinned) | JSON Schema 2020-12 |

`conformance/python/requirements.txt` carries `--hash` entries covering every
artifact PyPI publishes for each pin, generated by
`conformance/python/gen-requirements.py`; CI installs with
`--require-hashes`, so a substituted artifact fails closed.

**Update policy:** a dependency bump is its own reviewed change, never a
side effect. It names the advisory or release note that motivated it,
regenerates the lockfile/hash set with the bundled tooling, and must leave
the full three-runtime comparison green. Security advisories against a
pinned package are patched promptly; nothing else moves the pins.

## 6. Distribution (resolved PRUVZ-97 decision, extended by PRUVZ-101)

- One repository, one release stream: every package version ≡ the git tag
  ≡ the repository release (`1.6.0` at this writing), a stream already
  independent of `packetFormatVersion` (still `1.5.0`) and of
  `conformance/v1`. A verifier bug fix is a repository PATCH release and
  never implies a format change. `bin/check-versions.mjs` enforces the
  equality mechanically (in `npm test` and against the tag on release).
- Three channels, four artifacts, one source (PRUVZ-101):
  **npm** `@pruvz/evidence-packet` (Node CLI + library), **PyPI**
  `pruvz-evidence-packet` (built from `conformance/python/pruvz_verifier/`,
  console entry point `pruvz-verify`), **NuGet** `Pruvz.EvidencePacket`
  (library, `dotnet/Pruvz.EvidencePacket/`) and `Pruvz.EvidencePacket.Tool`
  (dotnet tool `pruvz-verify`, referencing the library). The published Python
  and .NET code is the exact code the conformance suite exercises — the
  Python harness imports the same package sources, the .NET harness
  references the same library project — so the packaged code and the gated
  code cannot drift. The public Git repository remains cloneable and
  authoritative. Installed packages carry the published schemas (and the
  verifier/v1 golden vectors) as package data / embedded resources, so they
  verify bundles completely offline with no repository clone.
- Every release is built from the immutable reviewed git tag and published
  via the release workflow
  ([`.github/workflows/release.yml`](../.github/workflows/release.yml)) on
  human dispatch only, never automatically on merge, and only after the
  conformance gate passes on the tagged bytes in repository mode, packaged
  mode and the isolated offline acceptance. Publication is idempotent per
  channel; a partial registry failure is resumed by re-dispatching the same
  tag (see `docs/VERSIONING.md` release step 6).

### One-time publishing setup (out-of-band manual actions, PRUVZ-101 AC 9)

Nothing below lives in chat history or session memory; this list is the
operational record.

- **npm** — the `@pruvz` scope and account exist with 2FA (PRUVZ-97). After
  the bootstrap `1.5.1` release: configure the package's **Trusted Publisher**
  on npmjs.com (`dorsharoni10/pruvz-evidence-packet`, workflow
  `release.yml`, environment blank), verify a publish succeeds through OIDC,
  then **revoke the short-lived `NPM_TOKEN` granular token and delete the
  repository secret** — the workflow no longer reads it, and after
  revocation no long-lived credential can publish the package. The publish
  job must not let anything write an auth token into `.npmrc` (in particular
  `actions/setup-node`'s `registry-url` input, which also exports a
  placeholder `NODE_AUTH_TOKEN`): npm would authenticate with that value
  instead of exchanging the job's OIDC token, and fail with a misleading
  `E404 ... or you do not have permission`.
- **PyPI** — create the account with 2FA, then add a **pending Trusted
  Publisher** for the project name `pruvz-evidence-packet` (owner
  `dorsharoni10`, repository `pruvz-evidence-packet`, workflow
  `release.yml`, environment blank) at pypi.org → Publishing. A pending
  publisher creates the project on its first OIDC publish — no API token
  ever exists. Attestations (PEP 740) are generated by default by
  `pypa/gh-action-pypi-publish`.
- **NuGet** — create the nuget.org account with 2FA. Preferred: a **Trusted
  Publishing policy** (nuget.org → account → Trusted Publishing) for
  `dorsharoni10/pruvz-evidence-packet`, workflow `release.yml`, then set the
  repository **variable** `NUGET_USER` to the nuget.org profile name — the
  workflow exchanges the job's OIDC token for a short-lived push key via
  `NuGet/login`. Trusted Publishing is still rolling out on nuget.org: if
  the account does not have it yet, create a **scoped API key** (push only,
  glob `Pruvz.EvidencePacket*`, shortest practical expiry) and store it as
  the `NUGET_API_KEY` repository secret; replace it with Trusted Publishing
  and delete the secret once available. Reserving the `Pruvz.` ID prefix on
  nuget.org is optional and can be requested later.
- All of this is free-tier: public packages on npm, PyPI and NuGet cost
  nothing, and no recurring infrastructure exists (PRUVZ-74 invariant 13).
