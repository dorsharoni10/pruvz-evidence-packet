"""Canonical commitment, format version 1 — independent Python implementation.

Implemented from docs/COMMITMENT.md alone (PRUVZ-97). This module shares no
code with the Node reference implementation or with pruvz-core; agreement is
proven byte for byte against commitment/v1/golden-vectors.json, which is the
whole point of it existing.

Number handling is where a Python runtime genuinely differs from Node, and the
differences are settled at PARSE time (see json_io.py): ``json.loads`` maps
``5.0`` to a float and ``-0`` to int ``0``, discarding exactly the distinctions
the value model judges. The harness parses every document with hooks that keep
them, so this module receives ints, floats (possibly integral) and the guarded
negative-zero marker — and judges the VALUE, never the spelling, exactly as the
specification requires.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

COMMITMENT_VERSION = "1"
DIGEST_SUITES = ("sha-256",)
COMMITMENT_KINDS = ("evidence-item", "evidence-packet")

_DOMAIN_TAG = "pruvz.ai/commitment"
_SEPARATOR = "\u0000"
_MAX_SAFE_INTEGER = 9007199254740991


class CommitmentError(Exception):
    """Every refusal. There is no lenient mode."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise CommitmentError(code, message)


_CONTROL_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _serialize_string(value: str, path: str) -> str:
    out = ['"']
    for index, char in enumerate(value):
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            # Python strings hold lone surrogates happily (json.loads admits
            # them); they are not text and cannot encode to UTF-8.
            _fail("LONE_SURROGATE", f"{path}: unpaired surrogate at index {index}")
        if char in _CONTROL_ESCAPES:
            out.append(_CONTROL_ESCAPES[char])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _utf16_key(name: str) -> bytes:
    # RFC 8785 orders members by UTF-16 code unit. Python's default string
    # order is by code point, which differs for astral characters — encoding
    # to UTF-16BE and comparing bytes IS code-unit order.
    return name.encode("utf-16-be", "surrogatepass")


def _serialize_value(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value, path)
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            _fail("INTEGER_OUT_OF_RANGE", f"{path}: integer {value} is outside the safe integer range")
        return str(value)
    if isinstance(value, float):
        # The value is judged, never the spelling: 5.0 denotes the integer 5.
        # A negative zero, a non-integral value, an infinity or a NaN is not a
        # committable integer.
        if math.copysign(1.0, value) < 0 and value == 0.0:
            _fail("NON_INTEGER_NUMBER", f"{path}: only integers may be committed (got -0)")
        if not math.isfinite(value) or not value.is_integer():
            _fail(
                "NON_INTEGER_NUMBER",
                f"{path}: only integers may be committed (got {value!r}); precision-sensitive "
                "values are committed as canonical decimal strings",
            )
        integral = int(value)
        if abs(integral) > _MAX_SAFE_INTEGER:
            _fail("INTEGER_OUT_OF_RANGE", f"{path}: integer {integral} is outside the safe integer range")
        return str(integral)
    if isinstance(value, list):
        return "[" + ",".join(_serialize_value(item, f"{path}/{index}") for index, item in enumerate(value)) + "]"
    if isinstance(value, dict):
        members = []
        for key in sorted(value.keys(), key=_utf16_key):
            member = value[key]
            members.append(f"{_serialize_string(key, f'{path}/{key}')}:{_serialize_value(member, f'{path}/{key}')}")
        return "{" + ",".join(members) + "}"
    _fail("UNSUPPORTED_VALUE", f"{path}: {type(value).__name__} cannot be committed")
    raise AssertionError("unreachable")


def canonicalize(document: Any) -> bytes:
    """RFC 8785 over the canonical value model, as UTF-8 bytes."""
    return _serialize_value(document, "$").encode("utf-8")


def commitment_input(kind: str, document: Any) -> bytes:
    if kind not in COMMITMENT_KINDS:
        _fail("UNKNOWN_KIND", f'Unknown commitment kind "{kind}". Known kinds: {", ".join(COMMITMENT_KINDS)}.')
    header = _SEPARATOR.join([_DOMAIN_TAG, COMMITMENT_VERSION, kind, ""])
    return header.encode("utf-8") + canonicalize(document)


def commitment_digest(kind: str, document: Any, suite: str = DIGEST_SUITES[0]) -> str:
    if suite not in DIGEST_SUITES:
        _fail("UNKNOWN_DIGEST_SUITE", f'Unknown digest suite "{suite}". Known suites: {", ".join(DIGEST_SUITES)}.')
    return "sha256:" + hashlib.sha256(commitment_input(kind, document)).hexdigest()


def require_supported(commitment_version: Any, digest_suite: Any = DIGEST_SUITES[0]) -> None:
    if commitment_version != COMMITMENT_VERSION:
        _fail(
            "UNKNOWN_COMMITMENT_VERSION",
            f'Unknown commitment version "{commitment_version}". This implementation speaks '
            f"version {COMMITMENT_VERSION}.",
        )
    if digest_suite not in DIGEST_SUITES:
        _fail("UNKNOWN_DIGEST_SUITE", f'Unknown digest suite "{digest_suite}".')


_EXACT_DECIMAL = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")


def canonical_decimal(text: Any) -> str:
    if not isinstance(text, str):
        _fail("NON_CANONICAL_DECIMAL", f"An exact decimal must be a string, not {type(text).__name__}")
    if _EXACT_DECIMAL.match(text) is None:
        _fail(
            "NON_CANONICAL_DECIMAL",
            f'"{text}" is not an exact decimal (no exponent, no plus sign, no leading zeros)',
        )
    integer, _, raw_fraction = text.partition(".")
    fraction = raw_fraction.rstrip("0")
    if integer == "-0" and fraction == "":
        _fail("NEGATIVE_ZERO", "Negative zero has no canonical decimal form; write 0")
    return integer if fraction == "" else f"{integer}.{fraction}"


_UTC_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")


def canonical_timestamp(text: Any) -> str:
    if not isinstance(text, str):
        _fail("NON_UTC_TIMESTAMP", f"A UTC timestamp must be a string, not {type(text).__name__}")
    match = _UTC_TIMESTAMP.match(text)
    if match is None:
        _fail(
            "NON_UTC_TIMESTAMP",
            f'"{text}" is not a UTC timestamp of the form YYYY-MM-DDTHH:MM:SS[.fraction]Z',
        )
    fraction = (match.group(2) or "").rstrip("0")
    return f"{match.group(1)}Z" if fraction == "" else f"{match.group(1)}.{fraction}Z"


_MONEY_MEMBERS = ("amount", "amountExact", "currency")
_CURRENCY = re.compile(r"^[A-Z]{3}$")


def is_money(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("currency"), str)


def canonical_money(money: Any, path: str = "$") -> dict:
    if not is_money(money):
        _fail("INVALID_MONEY", f"{path}: not a money value")
    if not isinstance(money.get("amountExact"), str):
        _fail(
            "MONEY_WITHOUT_EXACT_AMOUNT",
            f"{path}: money must carry amountExact (packet format 1.4.0 or later)",
        )
    unknown = [member for member in money.keys() if member not in _MONEY_MEMBERS]
    if unknown:
        _fail(
            "INVALID_MONEY",
            f"{path}: a money value carries only {', '.join(_MONEY_MEMBERS)}; refusing one that "
            f"also carries {', '.join(unknown)}",
        )
    if _CURRENCY.match(money["currency"]) is None:
        _fail("INVALID_CURRENCY", f"{path}: currency must be a three-letter uppercase ISO 4217 code")
    return {"amount": canonical_decimal(money["amountExact"]), "currency": money["currency"]}


def _normalize_packet_value(value: Any, path: str, key: Any) -> Any:
    if is_money(value):
        return canonical_money(value, path)
    if isinstance(value, list):
        return [_normalize_packet_value(item, f"{path}/{index}", None) for index, item in enumerate(value)]
    if isinstance(value, dict):
        return {member: _normalize_packet_value(value[member], f"{path}/{member}", member) for member in value.keys()}
    if isinstance(value, str) and key is not None and key.endswith("AtUtc"):
        return canonical_timestamp(value)
    return value


def evidence_packet_document(source: dict) -> dict:
    tenant_id = source.get("tenantId")
    packet = source.get("packet")
    if not isinstance(tenant_id, str) or tenant_id == "":
        _fail("MISSING_BINDING", "A commitment must bind a tenantId")
    if not isinstance(packet, dict):
        _fail("INVALID_DOCUMENT", "packet must be the parsed Evidence Packet document")
    action = packet.get("action")
    if not isinstance(action, dict) or not isinstance(action.get("actionId"), str):
        _fail("MISSING_BINDING", "packet.action.actionId is required to bind the commitment")
    return {
        "binding": {"actionId": action["actionId"], "tenantId": tenant_id},
        "content": _normalize_packet_value(packet, "$", None),
    }


EVIDENCE_ITEM_FIELDS = (
    "clientOperationId",
    "evidenceId",
    "occurredAtUtc",
    "payloadMetadata",
    "recordedAtUtc",
    "runId",
    "schemaVersion",
    "sequence",
    "source",
    "sourceReference",
    "summary",
    "trustLevel",
    "type",
)


def evidence_item_document(source: dict) -> dict:
    tenant_id = source.get("tenantId")
    action_id = source.get("actionId")
    item = source.get("item")
    if not isinstance(tenant_id, str) or tenant_id == "":
        _fail("MISSING_BINDING", "A commitment must bind a tenantId")
    if not isinstance(action_id, str) or action_id == "":
        _fail("MISSING_BINDING", "A commitment must bind an actionId")
    if not isinstance(item, dict):
        _fail("INVALID_DOCUMENT", "item must be the evidence item record")
    content = {}
    for field in EVIDENCE_ITEM_FIELDS:
        if field not in item:
            _fail("MISSING_FIELD", f"item.{field} is required: the commitment covers every field of the item")
        value = item[field]
        content[field] = canonical_timestamp(value) if field.endswith("AtUtc") else value
    return {"binding": {"actionId": action_id, "tenantId": tenant_id}, "content": content}
