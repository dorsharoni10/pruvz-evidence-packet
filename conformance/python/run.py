#!/usr/bin/env python3
"""The Python conformance harness (PRUVZ-97).

Replays every published vector — the four layer packs, the verifier/v1 golden
cases and the conformance/v1 adversarial suite — through the independent
Python implementation in pruvz_verifier/, and emits the same normalized
results document as the Node and .NET harnesses. It NEVER reads a vector's
expectation to produce an answer; bin/conformance-compare.mjs is the one
place expectations are read.

Usage: python conformance/python/run.py <out-file.json>
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

if os.environ.get("PRUVZ_CONFORMANCE_PACKAGED") == "1":
    # Packaged mode (PRUVZ-101): the harness must exercise the installed wheel,
    # not the working tree — so the working-tree package is NOT put on the
    # path, and the schemas must come from the wheel's package data (the
    # "package" source forbids any silent fallback to the repository's
    # schema/ directory, so a wheel that shipped without its schemas fails
    # loudly instead of passing against repository files).
    #
    # Python itself puts this script's directory at sys.path[0], which holds
    # the working-tree pruvz_verifier/ and would shadow the installed wheel —
    # strip it before importing anything.
    _here = os.path.normcase(os.path.dirname(os.path.abspath(__file__)))
    sys.path[:] = [
        entry for entry in sys.path if os.path.normcase(os.path.abspath(entry or os.getcwd())) != _here
    ]
    os.environ["PRUVZ_SCHEMA_SOURCE"] = "package"
    os.environ.pop("PRUVZ_SCHEMA_ROOT", None)
else:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # Judge the repository's schema/ bytes explicitly, even when a locally
    # built wheel left vendored package data lying in the working tree.
    os.environ.setdefault("PRUVZ_SCHEMA_ROOT", os.path.join(REPO_ROOT, "schema"))

from pruvz_verifier import anchoring, authority, evidence_log, json_io, registry, verify

if os.environ.get("PRUVZ_CONFORMANCE_PACKAGED") == "1" and os.path.normcase(os.path.abspath(verify.__file__)).startswith(
    os.path.normcase(REPO_ROOT) + os.sep
):
    print(
        f"FAIL  PRUVZ_CONFORMANCE_PACKAGED=1 but pruvz_verifier resolved to the working tree: {verify.__file__}",
        file=sys.stderr,
    )
    raise SystemExit(2)
from pruvz_verifier.canonical import (
    CommitmentError,
    canonical_decimal,
    canonical_timestamp,
    canonicalize,
    commitment_digest,
    evidence_item_document,
    evidence_packet_document,
    require_supported,
)


def load_vectors(name: str) -> dict:
    path = os.path.join(REPO_ROOT, name, "v1", "golden-vectors.json")
    with open(path, encoding="utf-8") as handle:
        return json_io.loads(handle.read())


commitment_vectors = load_vectors("commitment")
registry_vectors = load_vectors("trust-registry")
log_vectors = load_vectors("evidence-log")
anchoring_vectors = load_vectors("anchoring")
verifier_vectors = load_vectors("verifier")
conformance_vectors = load_vectors("conformance")


def clone(value):
    return json.loads(json.dumps(value))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code_of(fn):
    try:
        fn()
        return None
    except (CommitmentError, registry.TrustRegistryError, evidence_log.EvidenceLogError, anchoring.AnchorError) as error:
        return error.code


def normalize_report(report: dict) -> dict:
    return {
        "outcome": "REPORT",
        "verdict": report["verdict"],
        "reasonCodes": sorted(report["reasonCodes"]),
        "dimensions": {name: dimension.get("status", "COMPOSITE") for name, dimension in report["dimensions"].items()},
        "state": clone(report["state"]),
    }


# -- commitment/v1 -----------------------------------------------------------

def run_commitment() -> dict:
    out = {"decimals": [], "timestamps": [], "canonicalization": {}, "commitments": {}, "rejected": {}}
    for vector in commitment_vectors["decimals"]:
        out["decimals"].append(canonical_decimal(vector["input"]))
    for vector in commitment_vectors["timestamps"]:
        out["timestamps"].append(canonical_timestamp(vector["input"]))
    for vector in commitment_vectors["canonicalization"]:
        document = json_io.loads(vector["documentJson"]) if "documentJson" in vector else vector["document"]
        out["canonicalization"][vector["id"]] = canonicalize(document).decode("utf-8")
    for vector in commitment_vectors["commitments"]:
        document = (
            evidence_item_document(vector["source"])
            if vector["kind"] == "evidence-item"
            else evidence_packet_document(vector["source"])
        )
        out["commitments"][vector["id"]] = {
            "canonical": canonicalize(document).decode("utf-8"),
            "digest": commitment_digest(vector["kind"], document),
        }
    for vector in commitment_vectors["rejected"]:
        out["rejected"][vector["id"]] = code_of(lambda vector=vector: reject_one(vector))
    return out


def reject_one(vector: dict):
    document = json_io.loads(vector["documentJson"]) if "documentJson" in vector else vector.get("document")
    layer = vector["layer"]
    if layer == "decimal":
        return canonical_decimal(vector["input"])
    if layer == "timestamp":
        return canonical_timestamp(vector["input"])
    if layer == "canonicalization":
        return canonicalize(document)
    if layer == "commitment":
        return commitment_digest(vector["kind"], document)
    if layer == "digest":
        return commitment_digest(vector["kind"], document, vector["suite"])
    if layer == "supported":
        return require_supported(vector.get("commitmentVersion"), vector.get("suite"))
    if layer == "evidence-item-document":
        return evidence_item_document(vector["source"])
    if layer == "evidence-packet-document":
        return evidence_packet_document(vector["source"])
    raise AssertionError(f"unknown rejected-vector layer {layer!r}")


# -- trust-registry/v1 -------------------------------------------------------

def run_trust_registry() -> dict:
    out = {"thumbprints": {}, "digests": {}, "chainCases": {}, "refusalCases": {}, "sealCases": {}}
    for vector in registry_vectors["thumbprints"]:
        out["thumbprints"][vector["id"]] = registry.jwk_thumbprint(vector["jwk"])
    all_documents = {**registry_vectors["documents"], **registry_vectors["badDocuments"]}
    for name in registry_vectors["digests"].keys():
        manifest = registry.validate_registry_document(all_documents[name])["manifest"]
        out["digests"][name] = registry.manifest_digest(manifest)
    for scenario in registry_vectors["chainCases"]:
        pin = scenario["pinOverride"] if "pinOverride" in scenario else registry_vectors["pin"]
        try:
            state = None
            for name in scenario["establish"]:
                state = registry.accept_chain([all_documents[name]], registry_vectors["pin"], state)["state"]
            accepted = registry.accept_chain([all_documents[name] for name in scenario["attempt"]], pin, state)
            out["chainCases"][scenario["id"]] = {
                "outcome": "ACCEPT",
                "registryVersion": accepted["state"]["registryVersion"],
                "digest": accepted["state"]["digest"],
            }
        except registry.TrustRegistryError as error:
            out["chainCases"][scenario["id"]] = {"outcome": "REFUSE", "code": error.code}
    for scenario in registry_vectors["refusalCases"]:
        out["refusalCases"][scenario["id"]] = code_of(
            lambda scenario=scenario: registry.verify_manifest(all_documents[scenario["document"]], registry_vectors["pin"])
        )
    for scenario in registry_vectors["sealCases"]:
        manifest = registry.verify_manifest(registry_vectors["documents"][scenario["registry"]], registry_vectors["pin"])["manifest"]
        result = registry.verify_seal(
            registry_vectors["seals"][scenario["seal"]],
            manifest,
            registry_vectors["subjects"][scenario["subject"]],
            None
            if scenario["commitmentDigest"] is None
            else registry_vectors["expectedCommitmentDigests"][scenario["commitmentDigest"]],
        )
        out["sealCases"][scenario["id"]] = {
            "verdict": result["verdict"],
            "reasonCodes": sorted(result["reasonCodes"]),
            "dimensions": result["dimensions"],
        }
    return out


# -- evidence-log/v1 ---------------------------------------------------------

def run_evidence_log() -> dict:
    out = {
        "rfc6962LeafHashes": [],
        "rfc6962RootsBySize": [],
        "leafInputSha256": {},
        "leafHashes": [],
        "treeRootsBySize": [],
        "inclusion": [],
        "consistency": [],
        "checkpointSigningInputSha256": {},
        "acceptanceChain": [],
        "refusals": {},
    }
    known = log_vectors["rfc6962KnownAnswers"]
    known_hashes = [evidence_log.leaf_hash_of(bytes.fromhex(value)).hex() for value in known["leafDataHex"]]
    out["rfc6962LeafHashes"] = known_hashes
    out["rfc6962RootsBySize"] = [evidence_log.tree_head(known_hashes[: index + 1]) for index in range(len(known_hashes))]

    for seal_id, seal in log_vectors["seals"].items():
        out["leafInputSha256"][seal_id] = sha256_hex(evidence_log.leaf_input(seal))
        out["leafHashes"].append(evidence_log.seal_leaf_hash(seal))
    out["treeRootsBySize"] = [evidence_log.tree_head(out["leafHashes"][: index + 1]) for index in range(len(out["leafHashes"]))]

    for vector in log_vectors["tree"]["inclusion"]:
        out["inclusion"].append(
            code_of(
                lambda vector=vector: evidence_log.verify_inclusion(
                    out["leafHashes"][vector["leafIndex"]],
                    vector["leafIndex"],
                    vector["treeSize"],
                    vector["path"],
                    out["treeRootsBySize"][vector["treeSize"] - 1],
                )
            )
            or "VERIFIED"
        )
    for vector in log_vectors["tree"]["consistency"]:
        out["consistency"].append(
            code_of(
                lambda vector=vector: evidence_log.verify_consistency(
                    vector["fromSize"],
                    out["treeRootsBySize"][vector["fromSize"] - 1],
                    vector["toSize"],
                    out["treeRootsBySize"][vector["toSize"] - 1],
                    vector["proof"],
                )
            )
            or "VERIFIED"
        )

    for checkpoint_id, entry in log_vectors["checkpoints"].items():
        evidence_log.verify_checkpoint(entry["checkpoint"], entry["signature"], log_vectors["signingKey"]["jwk"])
        out["checkpointSigningInputSha256"][checkpoint_id] = sha256_hex(
            evidence_log.checkpoint_signing_input(entry["checkpoint"])
        )

    accepted = None
    for step in log_vectors["acceptanceChain"]["steps"]:
        checkpoint = log_vectors["checkpoints"][step["candidate"]]["checkpoint"]
        accepted = evidence_log.accept_checkpoint(accepted, checkpoint, step.get("consistencyProof"))
        out["acceptanceChain"].append(
            {"candidate": step["candidate"], "treeSize": accepted["treeSize"], "rootHash": accepted["rootHash"]}
        )

    for refusal in log_vectors["refusals"]:
        out["refusals"][refusal["id"]] = code_of(lambda refusal=refusal: replay_log_refusal(refusal))
    return out


def replay_log_refusal(refusal: dict):
    kind = refusal["kind"]
    if kind == "validateCheckpoint":
        return evidence_log.validate_checkpoint_document(refusal["document"])
    if kind == "leaf":
        return evidence_log.leaf_input(refusal["seal"])
    if kind == "inclusion":
        leaf_hash = (
            evidence_log.seal_leaf_hash(refusal["tamperedSeal"]) if "tamperedSeal" in refusal else refusal["leafHash"]
        )
        return evidence_log.verify_inclusion(
            leaf_hash, refusal["leafIndex"], refusal["treeSize"], refusal["path"], refusal["rootHashHex"]
        )
    if kind == "consistency":
        return evidence_log.verify_consistency(
            refusal["fromSize"], refusal["fromRootHash"], refusal["toSize"], refusal["toRootHash"], refusal["proof"]
        )
    if kind == "verifyCheckpoint":
        return evidence_log.verify_checkpoint(
            refusal["checkpoint"], refusal["signature"], refusal.get("jwk", log_vectors["signingKey"]["jwk"])
        )
    if kind == "acceptance":
        return evidence_log.accept_checkpoint(refusal["accepted"], refusal["candidate"], refusal.get("consistencyProof"))
    raise AssertionError(f"unknown refusal kind {kind!r}")


# -- anchoring/v1 ------------------------------------------------------------

def materialize_record(record: dict) -> dict:
    out = clone(record)
    token = ((out.get("receipt") or {}).get("token")) if isinstance(out.get("receipt"), dict) else None
    if isinstance(token, str) and token.startswith("@"):
        out["receipt"] = {**out["receipt"], "token": anchoring_vectors["receipts"][token[1:]]}
    return out


def run_anchoring() -> dict:
    out = {"deterministic": {}, "bindingCases": {}, "refusals": {}, "runtimeDivergence": {}}
    for vector in anchoring_vectors["deterministic"]:
        subject = anchoring_vectors["subjects"][vector["subjectRef"]]
        kind = "log-checkpoint" if "checkpoint" in subject else "trust-registry"
        nonce = base64.urlsafe_b64decode(vector["blindingNonce"] + "=" * (-len(vector["blindingNonce"]) % 4))
        anchor_input = anchoring.anchor_input(kind, nonce, subject)
        out["deterministic"][vector["id"]] = {
            "anchorInputLength": len(anchor_input),
            "anchorInputSha256": sha256_hex(anchor_input),
            "imprint": anchoring.anchor_imprint(kind, nonce, subject).hex(),
        }
    for vector in anchoring_vectors["bindingCases"]:
        record = materialize_record(vector["record"])
        subject = anchoring_vectors["subjects"][vector["subjectRef"]]
        binding = anchoring.verify_anchor_binding(record, subject)
        out["bindingCases"][vector["id"]] = {
            "genTime": binding["genTime"],
            "policyOid": binding["policyOid"],
            "imprint": binding["imprint"],
        }
    for vector in anchoring_vectors["refusals"]:
        record = materialize_record(vector["record"])
        subject = anchoring_vectors["subjects"][vector["subjectRef"]]
        out["refusals"][vector["id"]] = code_of(
            lambda record=record, subject=subject: anchoring.verify_anchor_binding(record, subject)
        )
    for vector in anchoring_vectors["runtimeDivergence"]:
        record = materialize_record(vector["record"])
        subject = anchoring_vectors["subjects"][vector["subjectRef"]]
        binds = code_of(lambda: anchoring.verify_anchor_binding(record, subject)) is None
        chain = authority.embedded_certificates(record["receipt"]["token"])
        half_two_code = None
        try:
            authority.verify_timestamp_authority(
                record["receipt"]["token"],
                [chain[-1]],
                anchoring.anchor_input(record["subject"]["kind"], record["blindingNonce"], subject),
            )
        except anchoring.AnchorError as error:
            half_two_code = error.code
        out["runtimeDivergence"][vector["id"]] = {"binds": binds, "halfTwoCode": half_two_code}
    return out


# -- verifier/v1 and conformance/v1 ------------------------------------------

def run_verifier_cases() -> dict:
    out = {}
    for golden_case in verifier_vectors["cases"]:
        pin = verifier_vectors["pin"]
        if golden_case["options"].get("pinRootOverride"):
            pin = {"issuer": pin["issuer"], "root": golden_case["options"]["pinRootOverride"]}
        report = verify.verify_bundle(
            clone(verifier_vectors["bundles"][golden_case["bundle"]]),
            pin,
            golden_case["options"].get("tenant"),
            verifier_vectors["tsaRoots"] if golden_case["options"].get("tsaRoots") else None,
        )
        out[golden_case["id"]] = normalize_report(report)
    return out


def run_conformance_cases() -> dict:
    out = {}
    for conformance_case in conformance_vectors["cases"]:
        results = []
        held_state = None
        for step in conformance_case["steps"]:
            raw_text = (
                conformance_vectors["rawBundles"][step["rawBundle"]]
                if "rawBundle" in step
                else json.dumps(conformance_vectors["bundles"][step["bundle"]])
            )
            try:
                bundle = json_io.loads(raw_text)
            except (json_io.DuplicateMemberError, ValueError):
                results.append({"outcome": "UNUSABLE_INPUT"})
                continue
            tsa = step["options"].get("tsaRoots")
            try:
                report = verify.verify_bundle(
                    bundle,
                    conformance_vectors["pin"],
                    step["options"].get("tenant"),
                    conformance_vectors["tsaRoots"]
                    if tsa is True
                    else (conformance_vectors["wrongTsaRoots"] if tsa == "wrong" else None),
                    None,
                    held_state if step["options"].get("state") == "held" else None,
                )
                held_state = clone(report["state"])
                results.append(normalize_report(report))
            except verify.VerifierError:
                results.append({"outcome": "UNUSABLE_INPUT"})
        out[conformance_case["id"]] = results
    return out


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python conformance/python/run.py <out-file.json>", file=sys.stderr)
        raise SystemExit(2)
    results = {
        "harnessResultsVersion": "1",
        "runtime": "python",
        "layers": {
            "commitment": run_commitment(),
            "trustRegistry": run_trust_registry(),
            "evidenceLog": run_evidence_log(),
            "anchoring": run_anchoring(),
        },
        "verifierV1": run_verifier_cases(),
        "conformance": run_conformance_cases(),
    }
    # The results directory is generated output and is not in git, so a fresh
    # clone has to create it before the first harness writes into it.
    os.makedirs(os.path.dirname(os.path.abspath(sys.argv[1])), exist_ok=True)
    with open(sys.argv[1], "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    print(f"python harness: wrote {sys.argv[1]}")


if __name__ == "__main__":
    main()
