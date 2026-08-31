"""The independent offline verifier — Python implementation (PRUVZ-97).

One entry point composes every verification layer over an exported bundle and
answers with the dimensional assurance report of docs/VERIFIER.md: verdict
FULLY_VERIFIED / PARTIALLY_VERIFIED / NOT_VERIFIED, per-dimension statuses,
machine-readable reason codes, per-record results and continuable state.
Missing material weakens and never passes; presented material that fails is a
refusal, never a downgrade; a cost-gated capability the producing deployment
did not run is reported honestly as absent and can never yield a full verdict.
"""

from __future__ import annotations

from typing import Any, Optional

from . import anchoring, authority, evidence_log, registry as registry_layer
from .canonical import (
    CommitmentError,
    commitment_digest,
    evidence_item_document,
    require_supported as require_commitment_supported,
)
from .validator import validate_packet

BUNDLE_FORMAT_VERSION = "1"

_BUNDLE_MEMBERS = (
    "bundleFormatVersion",
    "packet",
    "seals",
    "proofs",
    "checkpoints",
    "consistencyProofs",
    "trustRegistry",
    "anchors",
)
_STATE_MEMBERS = ("registry", "checkpoint")


class VerifierError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise VerifierError(code, message)


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _require_bundle(bundle: Any) -> dict:
    if not _is_object(bundle):
        _fail("BUNDLE_MALFORMED", "a verification bundle must be an object")
    if bundle.get("bundleFormatVersion") != BUNDLE_FORMAT_VERSION:
        _fail("BUNDLE_MALFORMED", f"this implementation speaks bundle format {BUNDLE_FORMAT_VERSION}")
    unknown = [member for member in bundle.keys() if member not in _BUNDLE_MEMBERS]
    if unknown:
        _fail("BUNDLE_MALFORMED", f"a bundle carries {', '.join(unknown)}; the member set is closed")
    packet = bundle.get("packet")
    if packet is not None and not _is_object(packet):
        _fail("BUNDLE_MALFORMED", "bundle.packet must be the packet document, or null")
    seals = bundle.get("seals") or {}
    if not _is_object(seals):
        _fail("BUNDLE_MALFORMED", "bundle.seals must map evidenceId to the served seal response")
    proofs = bundle.get("proofs") or {}
    if not _is_object(proofs):
        _fail("BUNDLE_MALFORMED", "bundle.proofs must map evidenceId to the served proof response")
    checkpoints = bundle.get("checkpoints")
    checkpoints = [] if checkpoints is None else checkpoints
    if not isinstance(checkpoints, list):
        _fail("BUNDLE_MALFORMED", "bundle.checkpoints must be an array")
    consistency_proofs = bundle.get("consistencyProofs")
    consistency_proofs = [] if consistency_proofs is None else consistency_proofs
    if not isinstance(consistency_proofs, list):
        _fail("BUNDLE_MALFORMED", "bundle.consistencyProofs must be an array")
    trust_registry = bundle.get("trustRegistry")
    if trust_registry is not None and (not isinstance(trust_registry, list) or len(trust_registry) == 0):
        _fail("BUNDLE_MALFORMED", "bundle.trustRegistry must be the served registry documents, or absent")
    anchors = bundle.get("anchors") or {}
    if not _is_object(anchors):
        _fail("BUNDLE_MALFORMED", "bundle.anchors must be an object")
    return {
        "packet": packet,
        "seals": seals,
        "proofs": proofs,
        "checkpoints": checkpoints,
        "consistencyProofs": consistency_proofs,
        "trustRegistry": trust_registry,
        "anchors": anchors,
    }


import re as _re

_ROOT_HASH = _re.compile(r"^sha256:[0-9a-f]{64}$")


def _is_safe_positive(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 9007199254740991


def _require_state(state: Any) -> None:
    if state is None:
        return
    if not _is_object(state):
        _fail("STATE_MALFORMED", "state must be the object a previous verifyBundle returned")
    unknown = [member for member in state.keys() if member not in _STATE_MEMBERS]
    if unknown:
        _fail("STATE_MALFORMED", f"held state carries {', '.join(unknown)}; the member set is closed")
    checkpoint = state.get("checkpoint")
    if checkpoint is None:
        return
    if (
        not _is_object(checkpoint)
        or not _is_safe_positive(checkpoint.get("checkpointSequence"))
        or not _is_safe_positive(checkpoint.get("treeSize"))
        or not isinstance(checkpoint.get("origin"), str)
        or checkpoint["origin"] == ""
        or not isinstance(checkpoint.get("rootHash"), str)
        or _ROOT_HASH.match(checkpoint["rootHash"]) is None
    ):
        _fail("STATE_MALFORMED", "state.checkpoint must carry checkpointSequence, origin, rootHash and treeSize")


def _require_pin(pin: Any) -> None:
    if not _is_object(pin) or not isinstance(pin.get("issuer"), str) or not isinstance(pin.get("root"), str):
        _fail("BUNDLE_MALFORMED", "verifyBundle requires a pinned { issuer, root }; there is no pinless mode")


def _anchor_records_of(entry: Any) -> list:
    if isinstance(entry, list):
        return entry
    if _is_object(entry) and isinstance(entry.get("anchors"), list):
        return entry["anchors"]
    _fail("BUNDLE_MALFORMED", "an anchors entry must be the served anchors response or an array of records")


def _supports_commitment_fields(version: Any) -> bool:
    try:
        major, minor = (int(part) for part in str(version).split(".")[:2])
    except ValueError:
        return False
    return major > 1 or (major == 1 and minor >= 5)


def verify_bundle(
    bundle: Any,
    pin: Any,
    expected_tenant_id: Optional[str] = None,
    tsa_roots: Optional[list] = None,
    tsa_policy_oids: Optional[list] = None,
    state: Any = None,
) -> dict:
    parts = _require_bundle(bundle)
    _require_pin(pin)
    _require_state(state)

    hard: set = set()
    weak: set = set()
    info: set = set()
    explanations: list = []

    def explain(code: str, message: str) -> None:
        explanations.append({"code": code, "message": message})

    # -- Trust registry ------------------------------------------------------
    registry = None
    if parts["trustRegistry"] is None:
        weak.add("REGISTRY_ABSENT")
        explain("REGISTRY_ABSENT", "The bundle carries no trust-registry documents.")
        registry_dimension = {"status": "ABSENT"}
    else:
        try:
            registry = registry_layer.accept_chain(
                parts["trustRegistry"], pin, (state or {}).get("registry") if state else None
            )
            for code in registry["reasonCodes"]:
                weak.add(code)
            registry_dimension = {
                "status": "ACCEPTED",
                "registryVersion": registry["manifest"]["registryVersion"],
                "rootStatus": registry["rootStatus"],
                "reasonCodes": list(registry["reasonCodes"]),
            }
            if not (state or {}).get("registry"):
                info.add("STATE_FIRST_USE")
        except registry_layer.TrustRegistryError as error:
            hard.add("REGISTRY_REJECTED")
            hard.add(error.code)
            explain(error.code, str(error))
            registry_dimension = {"status": "REJECTED", "reasonCode": error.code}

    # -- Packet --------------------------------------------------------------
    commitment_computable = False
    if parts["packet"] is None:
        weak.add("PACKET_ABSENT")
        weak.add("RETAINED_PROOF_ONLY")
        explain("RETAINED_PROOF_ONLY", "The bundle carries proof material without the packet payload.")
        packet_dimension = {"status": "ABSENT"}
    else:
        outcome = validate_packet(parts["packet"])
        if not outcome["valid"]:
            hard.add("PACKET_INVALID")
            explain("PACKET_INVALID", f"The packet does not conform to format {outcome['version']}.")
            packet_dimension = {"status": "INVALID", "packetFormatVersion": outcome["version"], "errors": outcome["errors"]}
        else:
            packet_dimension = {"status": "VALID", "packetFormatVersion": outcome["version"]}
            commitment_computable = _supports_commitment_fields(outcome["version"])
            if not commitment_computable:
                weak.add("COMMITMENT_FIELDS_UNAVAILABLE")
                explain("COMMITMENT_FIELDS_UNAVAILABLE", f"Packet format {outcome['version']} predates 1.5.0.")

    # -- Tenant binding ------------------------------------------------------
    envelope_tenants = set()
    for seal in parts["seals"].values():
        tenant = (((seal or {}).get("envelope") or {}).get("subject") or {}).get("tenantId") if _is_object(seal) else None
        if isinstance(tenant, str):
            envelope_tenants.add(tenant)
    if len(envelope_tenants) > 1:
        hard.add("TENANT_INCOHERENT")
        explain("TENANT_INCOHERENT", "The seals in this bundle name different tenants.")
    tenant_id = expected_tenant_id
    if tenant_id is None:
        if len(envelope_tenants) == 1:
            tenant_id = next(iter(envelope_tenants))
            info.add("TENANT_FROM_ENVELOPE")
    elif envelope_tenants and tenant_id not in envelope_tenants:
        hard.add("TENANT_MISMATCH")
        explain("TENANT_MISMATCH", f'The caller pinned tenant "{tenant_id}", but the bundle is sealed for another.')

    # -- Checkpoints ---------------------------------------------------------
    signed_checkpoints: dict = {}

    def consider_checkpoint(entry: Any, where: str) -> None:
        if not _is_object(entry) or not _is_object(entry.get("checkpoint")):
            hard.add("CHECKPOINT_INVALID")
            explain("CHECKPOINT_INVALID", f"{where} does not carry a checkpoint document")
            return
        sequence = entry["checkpoint"].get("checkpointSequence")
        held = signed_checkpoints.get(sequence)
        if held is not None and held != entry:
            hard.add("CHECKPOINT_CHAIN_REJECTED")
            hard.add("CHECKPOINT_FORK")
            explain("CHECKPOINT_FORK", f"The bundle carries two different checkpoints numbered {sequence}.")
            return
        signed_checkpoints[sequence] = entry

    for index, entry in enumerate(parts["checkpoints"]):
        consider_checkpoint(entry, f"bundle.checkpoints[{index}]")
    for evidence_id, proof in parts["proofs"].items():
        if _is_object(proof) and proof.get("checkpoint") is not None:
            consider_checkpoint(proof["checkpoint"], f"the inclusion proof of {evidence_id}")

    checkpoint_trust: dict = {}
    latest_profile = None
    profiles: set = set()
    for sequence in sorted(signed_checkpoints.keys(), key=lambda value: (isinstance(value, str), value)):
        entry = signed_checkpoints[sequence]
        trusted = False
        try:
            if registry is not None:
                key, reason = registry_layer.resolve_signing_key(
                    registry["manifest"], ((entry["checkpoint"].get("signer") or {}) if _is_object(entry["checkpoint"].get("signer")) else {}).get("keyId")
                )
                if reason is not None:
                    hard.add("CHECKPOINT_KEY_UNTRUSTED")
                    hard.add(reason)
                    explain(reason, f"Checkpoint {sequence} is signed by a key the registry does not recognize.")
                else:
                    state_when_signed = registry_layer.key_state_at(key, entry["checkpoint"]["issuedAt"])
                    if state_when_signed != "ACTIVE":
                        hard.add("CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY")
                        explain(
                            "CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY",
                            f"Checkpoint {sequence} was signed while its key was {state_when_signed}.",
                        )
                    else:
                        evidence_log.verify_checkpoint(entry["checkpoint"], entry.get("signature"), key["publicKey"])
                        trusted = True
                        if key["revokedAtUtc"] is not None:
                            weak.add("SIGNED_BEFORE_REVOCATION")
                            weak.add("COMMITTED_AT_SELF_ASSERTED")
            else:
                evidence_log.validate_checkpoint_document(entry["checkpoint"])
        except evidence_log.EvidenceLogError as error:
            if registry is not None:
                hard.add("CHECKPOINT_INVALID")
                hard.add(error.code)
                explain(error.code, f"Checkpoint {sequence}: {error}")
        except registry_layer.TrustRegistryError as error:
            if registry is not None:
                hard.add("CHECKPOINT_INVALID")
                hard.add(error.code)
                explain(error.code, f"Checkpoint {sequence}: {error}")
        checkpoint_trust[sequence] = trusted
        profile = entry["checkpoint"].get("assuranceProfile") if _is_object(entry.get("checkpoint")) else None
        if isinstance(profile, str):
            profiles.add(profile)
            latest_profile = profile

    consistency_by_sizes: dict = {}
    for proof in parts["consistencyProofs"]:
        if _is_object(proof):
            consistency_by_sizes[f"{proof.get('fromSize')}->{proof.get('toSize')}"] = proof.get("proof") or []

    def state_of(checkpoint: dict) -> dict:
        return {
            "checkpointSequence": checkpoint["checkpointSequence"],
            "origin": checkpoint["origin"],
            "rootHash": checkpoint["rootHash"],
            "treeSize": checkpoint["treeSize"],
        }

    held = (state or {}).get("checkpoint") if state else None
    accepted_state = held
    consistency_dimension = {"status": "NOT_APPLICABLE"}
    if len(signed_checkpoints) == 0:
        weak.add("CHECKPOINT_ABSENT")
        checkpoint_dimension = {"status": "ABSENT"}
    else:
        checkpoint_dimension = {
            "status": "ACCEPTED",
            "sequences": sorted(signed_checkpoints.keys(), key=lambda value: (isinstance(value, str), value)),
        }
        if held is None:
            info.add("STATE_FIRST_USE")
        ordered = [signed_checkpoints[key] for key in sorted(signed_checkpoints.keys(), key=lambda value: (isinstance(value, str), value))]
        if len(ordered) > 1 or held is not None:
            consistency_dimension = {"status": "PROVEN"}

        def connect(accepted: Any, entry: dict, what: str) -> dict:
            candidate = entry["checkpoint"]
            if accepted is None or accepted["treeSize"] == candidate.get("treeSize"):
                proof = []
            else:
                proof = consistency_by_sizes.get(f"{accepted['treeSize']}->{candidate.get('treeSize')}")
            if (
                accepted is not None
                and isinstance(candidate.get("treeSize"), int)
                and accepted["treeSize"] < candidate["treeSize"]
                and proof is None
            ):
                weak.add("CONSISTENCY_NOT_PROVEN")
                explain(
                    "CONSISTENCY_NOT_PROVEN",
                    f"No consistency proof connects tree size {accepted['treeSize']} to {candidate['treeSize']} ({what}).",
                )
                consistency_dimension["status"] = "NOT_PROVEN"
                return state_of(candidate)
            return evidence_log.accept_checkpoint(accepted, candidate, proof)

        try:
            internal = None
            retained = None
            newest_retained = None
            for entry in ordered:
                internal = connect(internal, entry, "inside the bundle")
                if checkpoint_trust.get((entry.get("checkpoint") or {}).get("checkpointSequence")) is True:
                    retained = internal
                    newest_retained = entry
            if newest_retained is None:
                weak.add("CHECKPOINT_KEY_UNTRUSTED")
                explain(
                    "CHECKPOINT_KEY_UNTRUSTED",
                    "No checkpoint in this bundle could be verified under the pinned registry.",
                )
                accepted_state = held
            elif held is None:
                accepted_state = retained
            else:
                if newest_retained["checkpoint"]["checkpointSequence"] >= held["checkpointSequence"]:
                    accepted_state = connect(held, newest_retained, "from the held verifier state")
                else:
                    weak.add("CONSISTENCY_NOT_PROVEN")
                    explain(
                        "CONSISTENCY_NOT_PROVEN",
                        "This bundle's newest verified checkpoint is older than the held state: a historical export.",
                    )
                    consistency_dimension["status"] = "NOT_PROVEN"
                    accepted_state = held
        except evidence_log.EvidenceLogError as error:
            hard.add("CHECKPOINT_CHAIN_REJECTED")
            hard.add(error.code)
            explain(error.code, str(error))
            checkpoint_dimension = {"status": "REJECTED", "reasonCode": error.code}
            consistency_dimension = {"status": "INVALID"}
            accepted_state = held

    # -- Evidence ------------------------------------------------------------
    packet_items = ((parts["packet"] or {}).get("evidence") or {}).get("items") or []
    items_by_id = {item["evidenceId"]: item for item in packet_items}
    evidence_ids = (
        [item["evidenceId"] for item in packet_items] if parts["packet"] is not None else list(parts["seals"].keys())
    )
    for evidence_id in parts["seals"].keys():
        if parts["packet"] is not None and evidence_id not in items_by_id:
            hard.add("SEAL_WITHOUT_EVIDENCE")
            explain("SEAL_WITHOUT_EVIDENCE", f"The bundle carries a seal for {evidence_id}, which the timeline does not contain.")

    action_id = ((parts["packet"] or {}).get("action") or {}).get("actionId")
    evidence_results = []
    for evidence_id in evidence_ids:
        item = items_by_id.get(evidence_id)
        seal = parts["seals"].get(evidence_id)
        entry: dict = {
            "evidenceId": evidence_id,
            "sequence": (item or {}).get("sequence")
            if item is not None
            else ((((seal or {}).get("envelope") or {}).get("subject") or {}).get("sequence") if _is_object(seal) else None),
        }

        expected_digest = None
        if item is not None and seal is not None and commitment_computable:
            try:
                envelope = (seal.get("envelope") or {}) if _is_object(seal) else {}
                commitment = envelope.get("commitment") or {}
                require_commitment_supported(commitment.get("version"), commitment.get("digestSuite"))
                if commitment.get("kind") != "evidence-item":
                    raise CommitmentError("UNSUPPORTED_KIND", "an evidence seal commits kind evidence-item")
                expected_digest = commitment_digest(
                    "evidence-item",
                    evidence_item_document(
                        {
                            "tenantId": tenant_id if tenant_id is not None else (envelope.get("subject") or {}).get("tenantId"),
                            "actionId": action_id,
                            "item": item,
                        }
                    ),
                    commitment.get("digestSuite") or "sha-256",
                )
                entry["commitment"] = "COMPUTED"
            except CommitmentError as error:
                weak.add(error.code)
                explain(error.code, f"Evidence {evidence_id}: {error}")
                entry["commitment"] = "NOT_COMPUTABLE"
        else:
            entry["commitment"] = "NOT_COMPUTABLE"

        if seal is None:
            weak.add("EVIDENCE_UNSEALED")
            entry["seal"] = {"status": "ABSENT"}
            entry["commitment"] = "NOT_CHECKED"
        elif registry is None:
            entry["seal"] = {"status": "NOT_CHECKED"}
            if expected_digest is not None:
                envelope_digest = (((seal.get("envelope") or {}).get("commitment")) or {}).get("digest")
                entry["commitment"] = "MATCHES_ENVELOPE" if expected_digest == envelope_digest else "MISMATCH"
                if entry["commitment"] == "MISMATCH":
                    hard.add("COMMITMENT_MISMATCH")
                    explain("COMMITMENT_MISMATCH", f"Evidence {evidence_id} does not hash to the digest its own envelope names.")
        else:
            try:
                if item is not None and tenant_id is not None:
                    expected_subject = {
                        "tenantId": tenant_id,
                        "actionId": action_id,
                        "evidenceId": evidence_id,
                        "sequence": item["sequence"],
                    }
                else:
                    expected_subject = ((seal.get("envelope") or {}).get("subject")) if _is_object(seal) else None
                result = registry_layer.verify_seal(
                    seal,
                    registry["manifest"],
                    expected_subject,
                    expected_digest,
                    registry["reasonCodes"],
                )
                entry["seal"] = {"status": result["verdict"], "dimensions": result["dimensions"], "reasonCodes": result["reasonCodes"]}
                if result["verdict"] == "INVALID":
                    hard.add("SEAL_INVALID")
                    for code in result["reasonCodes"]:
                        hard.add(code)
                    explain(
                        result["reasonCodes"][-1] if result["reasonCodes"] else "SEAL_INVALID",
                        f"Evidence {evidence_id}: the seal does not verify.",
                    )
                elif result["verdict"] == "PARTIAL":
                    for code in result["reasonCodes"]:
                        weak.add(code)
                content = result["dimensions"]["content"]
                if content == "MATCHES":
                    entry["commitment"] = "MATCHES"
                elif content == "MISMATCH":
                    entry["commitment"] = "MISMATCH"
                elif entry["commitment"] == "COMPUTED":
                    entry["commitment"] = "NOT_CHECKED"
                profile = (seal.get("envelope") or {}).get("assuranceProfile")
                if isinstance(profile, str):
                    profiles.add(profile)
            except registry_layer.TrustRegistryError as error:
                hard.add("SEAL_UNREADABLE")
                hard.add(error.code)
                explain(error.code, f"Evidence {evidence_id}: {error}")
                entry["seal"] = {"status": "INVALID", "reasonCode": error.code}

        proof = parts["proofs"].get(evidence_id)
        if proof is None:
            if seal is not None:
                weak.add("INCLUSION_PROOF_ABSENT")
            entry["inclusion"] = {"status": "ABSENT"}
        elif seal is None:
            weak.add("INCLUSION_PROOF_ABSENT")
            entry["inclusion"] = {"status": "NOT_CHECKED"}
        else:
            try:
                leaf_hash = evidence_log.seal_leaf_hash(seal)
                if proof.get("leafHash") != leaf_hash:
                    hard.add("LEAF_SEAL_MISMATCH")
                    explain("LEAF_SEAL_MISMATCH", f"Evidence {evidence_id}: the inclusion proof names a different leaf.")
                    entry["inclusion"] = {"status": "INVALID", "reasonCode": "LEAF_SEAL_MISMATCH"}
                else:
                    checkpoint = ((proof.get("checkpoint") or {}).get("checkpoint")) if _is_object(proof.get("checkpoint")) else None
                    evidence_log.verify_inclusion(
                        proof.get("leafHash"),
                        proof.get("leafIndex"),
                        (checkpoint or {}).get("treeSize"),
                        proof.get("path"),
                        str((checkpoint or {}).get("rootHash") or "").replace("sha256:", "", 1),
                    )
                    trusted = checkpoint_trust.get((checkpoint or {}).get("checkpointSequence")) is True
                    entry["inclusion"] = {
                        "status": "PROVEN" if trusted else "PROVEN_AGAINST_UNVERIFIED_CHECKPOINT",
                        "checkpointSequence": (checkpoint or {}).get("checkpointSequence"),
                    }
                    if not trusted:
                        weak.add("CHECKPOINT_KEY_UNTRUSTED")
            except evidence_log.EvidenceLogError as error:
                hard.add("INCLUSION_PROOF_INVALID")
                hard.add(error.code)
                explain(error.code, f"Evidence {evidence_id}: {error}")
                entry["inclusion"] = {"status": "INVALID", "reasonCode": error.code}
        evidence_results.append(entry)

    # -- Anchors -------------------------------------------------------------
    anchors_dimension: dict = {"checkpoints": {}, "trustRegistry": {}, "status": "ABSENT"}
    any_witnessed = False
    any_binding_only = False
    any_anchor_invalid = False
    any_anchor_pending = False

    def check_anchors(records: list, kind: str, subject: Any, label: str) -> list:
        nonlocal any_witnessed, any_binding_only, any_anchor_invalid, any_anchor_pending
        results = []
        for record in records:
            try:
                binding = anchoring.verify_anchor_binding(record, subject)
                if tsa_roots is None:
                    any_binding_only = True
                    results.append({"anchorId": record.get("anchorId"), "status": "BINDING_ONLY", "genTime": binding["genTime"]})
                else:
                    outcome = authority.verify_timestamp_authority(
                        record["receipt"]["token"],
                        tsa_roots,
                        anchoring.anchor_input(kind, record["blindingNonce"], subject),
                        tsa_policy_oids,
                    )
                    any_witnessed = True
                    results.append(
                        {
                            "anchorId": record.get("anchorId"),
                            "status": "WITNESSED",
                            "genTime": outcome["genTime"],
                            "policyOid": outcome["policyOid"],
                            "trustDomain": record.get("trustDomain"),
                        }
                    )
            except anchoring.AnchorError as error:
                if error.code == "ANCHOR_NOT_PRESENT":
                    any_anchor_pending = True
                    weak.add("ANCHOR_NOT_WITNESSED")
                    results.append(
                        {
                            "anchorId": record.get("anchorId") if _is_object(record) else None,
                            "status": record.get("status") if _is_object(record) else "UNKNOWN",
                        }
                    )
                else:
                    any_anchor_invalid = True
                    hard.add("ANCHOR_INVALID")
                    hard.add(error.code)
                    explain(error.code, f"{label}: {error}")
                    results.append(
                        {
                            "anchorId": record.get("anchorId") if _is_object(record) else None,
                            "status": "INVALID",
                            "reasonCode": error.code,
                        }
                    )
        return results

    checkpoint_anchors = parts["anchors"].get("checkpoints") if _is_object(parts["anchors"].get("checkpoints")) else {}
    for sequence_text, entry in (checkpoint_anchors or {}).items():
        try:
            sequence = int(sequence_text)
        except ValueError:
            sequence = None
        signed_checkpoint = signed_checkpoints.get(sequence)
        if signed_checkpoint is None:
            weak.add("ANCHOR_NOT_WITNESSED")
            explain(
                "ANCHOR_NOT_WITNESSED",
                f"The bundle carries anchors for checkpoint {sequence_text} but not that signed checkpoint itself.",
            )
            continue
        anchors_dimension["checkpoints"][sequence_text] = check_anchors(
            _anchor_records_of(entry),
            "log-checkpoint",
            {"checkpoint": signed_checkpoint["checkpoint"], "signature": signed_checkpoint["signature"]},
            f"checkpoint {sequence_text} anchor",
        )

    registry_anchors = parts["anchors"].get("trustRegistry") if _is_object(parts["anchors"].get("trustRegistry")) else {}
    for version_text, entry in (registry_anchors or {}).items():
        document = None
        for candidate in parts["trustRegistry"] or []:
            manifest = (candidate or {}).get("manifest") if _is_object(candidate) else None
            if _is_object(manifest) and str(manifest.get("registryVersion")) == str(version_text):
                document = candidate
                break
        if document is None:
            weak.add("ANCHOR_NOT_WITNESSED")
            explain(
                "ANCHOR_NOT_WITNESSED",
                f"The bundle carries anchors for trust-registry version {version_text} but not that registry document.",
            )
            continue
        anchors_dimension["trustRegistry"][version_text] = check_anchors(
            _anchor_records_of(entry),
            "trust-registry",
            {"manifest": document["manifest"], "signatures": document["signatures"]},
            f"trust-registry version {version_text} anchor",
        )

    any_anchor_records = len(anchors_dimension["checkpoints"]) > 0 or len(anchors_dimension["trustRegistry"]) > 0
    if not any_anchor_records:
        weak.add("ANCHORS_ABSENT")
        if latest_profile == "PRE_CUSTOMER_DEFAULT":
            weak.add("COST_GATED_CAPABILITY_ABSENT")
            explain(
                "COST_GATED_CAPABILITY_ABSENT",
                "External anchoring is cost-gated and this deployment profile does not run it.",
            )
        anchors_dimension["status"] = "ABSENT"
    elif any_anchor_invalid:
        anchors_dimension["status"] = "INVALID"
    elif any_witnessed and not any_binding_only and not any_anchor_pending:
        anchors_dimension["status"] = "WITNESSED"
    elif any_binding_only:
        weak.add("ANCHOR_AUTHORITY_NOT_EVALUATED")
        explain(
            "ANCHOR_AUTHORITY_NOT_EVALUATED",
            "Anchor bindings were checked, but no timestamp-authority roots were pinned.",
        )
        anchors_dimension["status"] = "BINDING_ONLY"
    else:
        anchors_dimension["status"] = "PARTIAL"
    if any_anchor_records and len(anchors_dimension["trustRegistry"]) == 0:
        weak.add("REGISTRY_NOT_WITNESSED")

    # -- Assurance profile ---------------------------------------------------
    if latest_profile is None and len(profiles) == 1:
        latest_profile = next(iter(profiles))
    if len(profiles) == 0:
        profile_dimension = {"status": "UNKNOWN", "declared": []}
    elif len(profiles) == 1:
        profile_dimension = {"status": "CONSISTENT", "declared": list(profiles)}
    else:
        weak.add("PROFILE_MIXED")
        explain("PROFILE_MIXED", f"The material in this bundle was produced under {len(profiles)} different assurance profiles.")
        profile_dimension = {"status": "MIXED", "declared": sorted(profiles)}

    # -- Roll-up -------------------------------------------------------------
    seal_statuses = [(entry.get("seal") or {}).get("status") for entry in evidence_results]
    if any(status == "INVALID" for status in seal_statuses):
        seals_status = "INVALID"
    elif any(status in ("ABSENT", "NOT_CHECKED") for status in seal_statuses):
        seals_status = "INCOMPLETE"
    elif any(status == "PARTIAL" for status in seal_statuses):
        seals_status = "PARTIAL"
    elif len(seal_statuses) > 0:
        seals_status = "VALID"
    else:
        seals_status = "ABSENT"

    commitment_states = [entry.get("commitment") for entry in evidence_results]
    if any(status == "MISMATCH" for status in commitment_states):
        commitment_status = "MISMATCH"
    elif len(commitment_states) > 0 and all(status == "MATCHES" for status in commitment_states):
        commitment_status = "MATCHES"
    elif any(status in ("MATCHES", "MATCHES_ENVELOPE") for status in commitment_states):
        commitment_status = "PARTIAL"
    else:
        commitment_status = "NOT_CHECKED"

    inclusion_states = [(entry.get("inclusion") or {}).get("status") for entry in evidence_results]
    if any(status == "INVALID" for status in inclusion_states):
        inclusion_status = "INVALID"
    elif len(inclusion_states) > 0 and all(status == "PROVEN" for status in inclusion_states):
        inclusion_status = "PROVEN"
    elif any(status in ("PROVEN", "PROVEN_AGAINST_UNVERIFIED_CHECKPOINT") for status in inclusion_states):
        inclusion_status = "PARTIAL"
    else:
        inclusion_status = "ABSENT"

    unsupported_codes = (
        "UNKNOWN_SUITE",
        "UNKNOWN_ENVELOPE_VERSION",
        "UNKNOWN_COMMITMENT_VERSION",
        "UNKNOWN_DIGEST_SUITE",
        "UNKNOWN_KEY_USE",
        "UNSUPPORTED_KIND",
        "ANCHOR_SUITE_UNSUPPORTED",
    )
    suite_support_status = (
        "UNSUPPORTED" if any(code in hard or code in weak for code in unsupported_codes) else "SUPPORTED"
    )

    verdict = "NOT_VERIFIED" if hard else ("PARTIALLY_VERIFIED" if weak else "FULLY_VERIFIED")

    return {
        "verifierFormatVersion": "1",
        "verdict": verdict,
        "reasonCodes": sorted(set().union(hard, weak, info)),
        "explanations": explanations,
        "dimensions": {
            "packet": packet_dimension,
            "commitment": {"status": commitment_status},
            "seals": {"status": seals_status},
            "trustRegistry": registry_dimension,
            "logInclusion": {"status": inclusion_status},
            "logConsistency": consistency_dimension,
            "checkpoints": checkpoint_dimension,
            "anchors": anchors_dimension,
            "assuranceProfile": profile_dimension,
            "suiteSupport": {"status": suite_support_status},
            "retention": {"status": "PROOF_ONLY" if parts["packet"] is None else "PAYLOAD_PRESENT"},
        },
        "evidence": evidence_results,
        "state": {
            "registry": (registry or {}).get("state") if registry else ((state or {}).get("registry") if state else None),
            "checkpoint": accepted_state,
        },
    }
