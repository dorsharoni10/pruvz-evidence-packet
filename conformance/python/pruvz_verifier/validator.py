"""Packet validation — JSON Schema (draft 2020-12) plus the packet-level
consistency rules JSON Schema cannot express (docs/CONFORMANCE.md).

The schemas are the published ``schema/vX.Y.Z`` releases of this repository;
schema evaluation is the maintained ``jsonschema`` library. The consistency
rules are ported from the specification behind lib/validator.mjs: sequence
contiguity, id uniqueness, review/decision agreement, execution/verification
coupling, deadline-dependent mismatch reasons, and the two-representation
money rule.
"""

from __future__ import annotations

import json
import os
from typing import Any, List

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .canonical import CommitmentError, canonical_decimal, is_money

SUPPORTED_VERSIONS = ("1.5.0", "1.4.0", "1.3.0", "1.2.0", "1.1.0", "1.0.0")

_here = os.path.dirname(os.path.abspath(__file__))


def _resolve_schema_root() -> str:
    # PRUVZ_SCHEMA_ROOT always wins (explicit override). Otherwise an installed
    # package carries the published schemas as package data under _data/, so it
    # is self-sufficient offline (PRUVZ-101); a repository checkout has no
    # _data and falls back to the repository's schema/ directory.
    # PRUVZ_SCHEMA_SOURCE=package forbids that fallback, so packaged-mode
    # conformance runs fail loudly on a wheel that shipped without its schemas
    # instead of silently passing against repository files.
    explicit = os.environ.get("PRUVZ_SCHEMA_ROOT")
    if explicit is not None:
        return explicit
    packaged = os.path.join(_here, "_data", "schema")
    if os.environ.get("PRUVZ_SCHEMA_SOURCE") == "package" or os.path.isdir(packaged):
        return packaged
    return os.path.normpath(os.path.join(_here, "..", "..", "..", "schema"))


_schema_root = _resolve_schema_root()

_compiled: dict = {}


def _supports_reverification(version: str) -> bool:
    major, minor = (int(part) for part in version.split(".")[:2])
    return major > 1 or (major == 1 and minor >= 3)


def _supports_exact_amount(version: str) -> bool:
    major, minor = (int(part) for part in version.split(".")[:2])
    return major > 1 or (major == 1 and minor >= 4)


def create_validator(version: str) -> Draft202012Validator:
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f'Unsupported packet format version "{version}"')
    if version not in _compiled:
        directory = os.path.join(_schema_root, f"v{version}")

        def load(name: str) -> dict:
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                return json.load(handle)

        resources = [load("action.schema.json"), load("evidence.schema.json")]
        packet_schema = load("evidence-packet.schema.json")
        registry = Registry()
        for schema in resources + [packet_schema]:
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        _compiled[version] = Draft202012Validator(packet_schema, registry=registry)
    return _compiled[version]


def _consistency_error(instance_path: str, message: str) -> dict:
    return {"instancePath": instance_path, "keyword": "packetConsistency", "message": message}


def _money_values(value: Any, pointer: str, found: list) -> list:
    if isinstance(value, list):
        for index, item in enumerate(value):
            _money_values(item, f"{pointer}/{index}", found)
    elif isinstance(value, dict):
        if is_money(value):
            found.append((pointer, value))
        for key in value.keys():
            _money_values(value[key], f"{pointer}/{key}", found)
    return found


def _representations_agree(money: dict) -> bool:
    try:
        return float(canonical_decimal(money.get("amountExact"))) == float(money.get("amount"))
    except (CommitmentError, TypeError, ValueError):
        return False


def packet_consistency_errors(packet: dict, version: str) -> List[dict]:
    errors: List[dict] = []
    action = packet["action"]
    evidence = packet["evidence"]
    items = evidence["items"]
    reverification = _supports_reverification(version)

    if action["actionId"] != evidence["actionId"]:
        errors.append(_consistency_error("/evidence/actionId", "must equal /action/actionId"))
    for index, item in enumerate(items):
        if item["sequence"] != index + 1:
            errors.append(
                _consistency_error(f"/evidence/items/{index}/sequence", f"must be {index + 1}")
            )

    seen: dict = {}
    for index, item in enumerate(items):
        if item["evidenceId"] in seen:
            errors.append(_consistency_error(f"/evidence/items/{index}/evidenceId", "must be unique"))
        else:
            seen[item["evidenceId"]] = index

    decision_items = [item for item in items if item["type"] == "HUMAN_REVIEW_DECISION"]
    if "review" not in action:
        if action.get("reviewState") == "DECIDED" and len(decision_items) == 0:
            errors.append(_consistency_error("/action/reviewState", "DECIDED requires a HUMAN_REVIEW_DECISION item"))
        if len(decision_items) > 0 and action.get("reviewState") != "DECIDED":
            errors.append(_consistency_error("/action/reviewState", "must be DECIDED"))
    else:
        errors.extend(_review_consistency_errors(action, decision_items, reverification))

    resolved_externally = (
        action.get("review") is not None
        and any(decision["decision"] == "RESOLVED_EXTERNALLY" for decision in action["review"]["decisions"])
    )
    if reverification and action.get("reverificationTiming") is not None and not resolved_externally:
        errors.append(
            _consistency_error("/action/reverificationTiming", "requires a RESOLVED_EXTERNALLY decision")
        )
    if reverification and any(item["type"] == "FOLLOW_UP_INDEPENDENT_READBACK" for item in items):
        if not resolved_externally:
            errors.append(_consistency_error("/action/review", "FOLLOW_UP_INDEPENDENT_READBACK requires RESOLVED_EXTERNALLY"))
        if action.get("reverificationTiming") is None:
            errors.append(_consistency_error("/action/reverificationTiming", "the fresh window must be recorded"))

    execution_status = action["executionStatus"]
    started = action["executionStartedAtUtc"]
    completed = action["executionCompletedAtUtc"]
    if execution_status == "RECEIVED" and started is not None:
        errors.append(_consistency_error("/action/executionStartedAtUtc", "must be null while RECEIVED"))
    if execution_status == "EXECUTING" and started is None:
        errors.append(_consistency_error("/action/executionStartedAtUtc", "must be set when EXECUTING"))
    if execution_status == "COMPLETED" and completed is None:
        errors.append(_consistency_error("/action/executionCompletedAtUtc", "must be set when COMPLETED"))
    if execution_status != "COMPLETED" and completed is not None:
        errors.append(_consistency_error("/action/executionCompletedAtUtc", f"must be null while {execution_status}"))

    if action["verificationStatus"] != "NOT_STARTED" and execution_status != "COMPLETED":
        errors.append(
            _consistency_error("/action/verificationStatus", f"{action['verificationStatus']} requires executionStatus COMPLETED")
        )

    if (
        action.get("mismatch")
        and action["mismatch"].get("mismatchReason") == "EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE"
        and action.get("verificationTiming")
        and action["verificationTiming"].get("deadlineAtUtc") is None
    ):
        errors.append(
            _consistency_error("/action/mismatch/mismatchReason", "requires a resolved verificationTiming.deadlineAtUtc")
        )

    if _supports_exact_amount(version):
        for pointer, money in _money_values(action, "/action", []):
            if not _representations_agree(money):
                errors.append(
                    _consistency_error(f"{pointer}/amountExact", "must denote the same amount as the JSON number beside it")
                )

    return errors


def _review_consistency_errors(action: dict, decision_items: list, reverification: bool) -> List[dict]:
    errors: List[dict] = []
    review = action["review"]
    if review is None:
        if len(decision_items) > 0:
            errors.append(_consistency_error("/action/review", "must be present when the timeline carries a HUMAN_REVIEW_DECISION item"))
        return errors

    decisions = review["decisions"]
    if len(decisions) != len(decision_items):
        errors.append(_consistency_error("/action/review/decisions", "must list exactly one decision per HUMAN_REVIEW_DECISION item"))
    for index, decision in enumerate(decisions):
        item = decision_items[index] if index < len(decision_items) else None
        if item is None or item["evidenceId"] != decision["evidenceId"] or item["sequence"] != decision["evidenceSequence"]:
            errors.append(_consistency_error(f"/action/review/decisions/{index}/evidenceId", "must name the matching HUMAN_REVIEW_DECISION item"))
        if index > 0 and decisions[index - 1]["newReviewState"] != decision["previousReviewState"]:
            worker_return = (
                reverification
                and decisions[index - 1]["decision"] == "RESOLVED_EXTERNALLY"
                and decision["previousReviewState"] == "PENDING_REVIEW"
            )
            if not worker_return:
                errors.append(
                    _consistency_error(f"/action/review/decisions/{index}/previousReviewState", "must equal the previous decision's newReviewState")
                )
    if len(decisions) > 0 and decisions[0]["previousReviewState"] != "PENDING_REVIEW":
        errors.append(_consistency_error("/action/review/decisions/0/previousReviewState", "must be PENDING_REVIEW"))

    last = decisions[-1] if len(decisions) > 0 else None
    if json.dumps(review.get("latestDecision"), sort_keys=True) != json.dumps(last, sort_keys=True):
        errors.append(_consistency_error("/action/review/latestDecision", "must equal the last entry of decisions"))

    expected_state = "PENDING_REVIEW" if last is None else last["newReviewState"]
    if action["reviewState"] != expected_state:
        worker_moved = (
            reverification
            and last is not None
            and last["decision"] == "RESOLVED_EXTERNALLY"
            and (
                (action["reviewState"] == "DECIDED" and action["verificationStatus"] == "VERIFIED")
                or (
                    action["reviewState"] == "PENDING_REVIEW"
                    and action["verificationStatus"] in ("OUTCOME_MISMATCH", "VERIFICATION_FAILED")
                )
            )
        )
        if not worker_moved:
            errors.append(_consistency_error("/action/reviewState", "must follow the latest decision"))

    if reverification:
        if action["verificationStatus"] == "VERIFIED" and (last is None or last["decision"] != "RESOLVED_EXTERNALLY"):
            errors.append(_consistency_error("/action/review", "a VERIFIED action carries a review only after RESOLVED_EXTERNALLY"))
        if review.get("independentlyConfirmed") is True and (last is None or last["decision"] != "RESOLVED_EXTERNALLY"):
            errors.append(_consistency_error("/action/review/independentlyConfirmed", "true requires RESOLVED_EXTERNALLY"))

    return errors


def validate_packet(packet: Any) -> dict:
    declared = packet.get("packetFormatVersion") if isinstance(packet, dict) else None
    version = declared if declared in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
    validator = create_validator(version)
    schema_errors = [
        {"instancePath": "/" + "/".join(str(part) for part in error.absolute_path), "message": error.message}
        for error in validator.iter_errors(packet)
    ]
    if schema_errors:
        return {"valid": False, "version": version, "errors": schema_errors}
    errors = packet_consistency_errors(packet, version)
    return {"valid": len(errors) == 0, "version": version, "errors": errors}
