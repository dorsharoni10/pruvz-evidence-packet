"""External anchoring, format version 1 — independent Python implementation.

Implemented from docs/ANCHORING.md (PRUVZ-97). Half one (the binding) is the
Pruvz-specific composition; the RFC 3161 token is parsed with the maintained
``asn1crypto`` library, and half two (the authority) lives in authority.py.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any

from asn1crypto import cms, tsp

from .canonical import CommitmentError, canonical_timestamp, canonicalize
from .evidence_log import EvidenceLogError, validate_checkpoint_document

ANCHORING_FORMAT_VERSION = "1"
SUBJECT_DOMAIN_TAGS = {
    "log-checkpoint": "pruvz.ai/log-anchor",
    "trust-registry": "pruvz.ai/trust-registry-anchor",
}
_SEPARATOR = "\u0000"
BLINDING_NONCE_BYTES = 32
MIN_REQUEST_NONCE_BYTES = 8
ANCHOR_STATUSES = ("ANCHORED", "PENDING", "FAILED")
RECEIPT_KIND = "rfc3161-timestamp-token"
_MAX_BOUND_TEXT_LENGTH = 512
_MAX_SAFE_INTEGER = 9007199254740991
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_IMPRINT_ALGORITHMS = {OID_SHA256: "sha-256"}


class AnchorError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise AnchorError(code, message)


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _bound_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or value == "":
        _fail("ANCHOR_MALFORMED", f"{field} is required")
    if len(value) > _MAX_BOUND_TEXT_LENGTH:
        _fail("ANCHOR_MALFORMED", f"{field} must not exceed {_MAX_BOUND_TEXT_LENGTH} characters")
    if _PRINTABLE_ASCII.match(value) is None:
        _fail("ANCHOR_MALFORMED", f"{field} must be printable ASCII")
    return value


def decode_base64url(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or value == "" or _BASE64URL.match(value) is None:
        _fail("ANCHOR_MALFORMED", f"{field} must be unpadded base64url")
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii") != value:
        _fail("ANCHOR_MALFORMED", f"{field} is not a canonical unpadded base64url encoding")
    return data


def decode_base64(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or value == "" or _BASE64.match(value) is None:
        _fail("ANCHOR_RECEIPT_MALFORMED", f"{field} must be base64")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        _fail("ANCHOR_RECEIPT_MALFORMED", f"{field} must be base64")
    if base64.b64encode(data).decode("ascii") != value:
        _fail("ANCHOR_RECEIPT_MALFORMED", f"{field} is not a canonical base64 encoding")
    return data


def _unsigned(data: bytes) -> bytes:
    start = 0
    while start < len(data) - 1 and data[start] == 0:
        start += 1
    return data[start:]


def require_supported(format_version: Any) -> None:
    if format_version != ANCHORING_FORMAT_VERSION:
        shown = "(none)" if format_version is None else f'"{format_version}"'
        _fail("UNKNOWN_ANCHOR_VERSION", f"Unknown anchoring version {shown}.")


# ── Subjects ────────────────────────────────────────────────────────────────

def subject_material(kind: Any, subject: Any) -> dict:
    if kind not in SUBJECT_DOMAIN_TAGS:
        _fail("ANCHOR_MALFORMED", f'subject.kind "{kind}" is not a subject this format anchors')
    if not _is_object(subject):
        _fail("ANCHOR_MALFORMED", "a subject must be an object")

    if kind == "log-checkpoint":
        unknown = [member for member in subject.keys() if member not in ("checkpoint", "signature")]
        if unknown:
            _fail("ANCHOR_MALFORMED", f"a log-checkpoint subject holds exactly checkpoint and signature; got {', '.join(unknown)}")
        if not _is_object(subject.get("checkpoint")):
            _fail("ANCHOR_MALFORMED", "a log-checkpoint subject must carry a checkpoint object")
        try:
            validate_checkpoint_document(subject["checkpoint"])
        except EvidenceLogError as error:
            _fail("ANCHOR_MALFORMED", f"the checkpoint being anchored is not valid: {error}")
        decode_base64url(subject.get("signature"), "subject.signature")
        return {
            "document": {"checkpoint": subject["checkpoint"], "signature": subject["signature"]},
            "origin": subject["checkpoint"]["origin"],
            "subjectVersion": subject["checkpoint"]["checkpointSequence"],
        }

    if not _is_object(subject.get("manifest")):
        _fail("ANCHOR_MALFORMED", "a trust-registry subject must carry a manifest object")
    if not isinstance(subject.get("signatures"), list) or len(subject["signatures"]) == 0:
        _fail("ANCHOR_MALFORMED", "a trust-registry subject must carry a non-empty signatures array")
    issuer = subject["manifest"].get("issuer")
    registry_version = subject["manifest"].get("registryVersion")
    _bound_text(issuer, "subject.manifest.issuer")
    if not isinstance(registry_version, int) or isinstance(registry_version, bool) or registry_version < 1:
        _fail("ANCHOR_MALFORMED", "subject.manifest.registryVersion must be a positive integer")
    return {
        "document": {"manifest": subject["manifest"], "signatures": subject["signatures"]},
        "origin": issuer,
        "subjectVersion": registry_version,
    }


def anchor_input(kind: Any, blinding_nonce: Any, subject: Any) -> bytes:
    material = subject_material(kind, subject)
    nonce = blinding_nonce if isinstance(blinding_nonce, (bytes, bytearray)) else decode_base64url(blinding_nonce, "blindingNonce")
    if len(nonce) != BLINDING_NONCE_BYTES:
        _fail("ANCHOR_MALFORMED", f"a blinding nonce is exactly {BLINDING_NONCE_BYTES} bytes; got {len(nonce)}")
    header = _SEPARATOR.join([SUBJECT_DOMAIN_TAGS[kind], ANCHORING_FORMAT_VERSION, ""])
    try:
        body = canonicalize(material["document"])
    except CommitmentError as error:
        _fail("ANCHOR_MALFORMED", f"a subject cannot be canonicalized: {error}")
    return header.encode("utf-8") + bytes(nonce) + body


def anchor_imprint(kind: Any, blinding_nonce: Any, subject: Any) -> bytes:
    return hashlib.sha256(anchor_input(kind, blinding_nonce, subject)).digest()


# ── The anchor record ───────────────────────────────────────────────────────

_RECORD_MEMBERS = ("anchorId", "blindingNonce", "receipt", "requestNonce", "status", "subject", "trustDomain", "version")
_SUBJECT_MEMBERS = ("kind", "origin", "subjectVersion")
_RECEIPT_MEMBERS = ("kind", "token")


def validate_anchor_record(record: Any) -> dict:
    if not _is_object(record):
        _fail("ANCHOR_MALFORMED", "an anchor record must be an object")
    require_supported(record.get("version"))
    unknown = [member for member in record.keys() if member not in _RECORD_MEMBERS]
    if unknown:
        _fail("ANCHOR_MALFORMED", f"an anchor record carries {', '.join(unknown)}; the member set is closed")
    missing = [member for member in _RECORD_MEMBERS if member not in record]
    if missing:
        _fail("ANCHOR_MALFORMED", f"an anchor record is missing {', '.join(missing)}")
    _bound_text(record["anchorId"], "anchorId")
    _bound_text(record["trustDomain"], "trustDomain")
    if record["status"] not in ANCHOR_STATUSES:
        _fail("ANCHOR_MALFORMED", f"status must be one of {', '.join(ANCHOR_STATUSES)}")
    subject = record["subject"]
    if not _is_object(subject):
        _fail("ANCHOR_MALFORMED", "subject must be an object")
    subject_unknown = [member for member in subject.keys() if member not in _SUBJECT_MEMBERS]
    if subject_unknown:
        _fail("ANCHOR_MALFORMED", f"subject carries {', '.join(subject_unknown)}; it holds exactly {', '.join(_SUBJECT_MEMBERS)}")
    if subject.get("kind") not in SUBJECT_DOMAIN_TAGS:
        _fail("ANCHOR_MALFORMED", f"subject.kind must be one of {', '.join(SUBJECT_DOMAIN_TAGS)}")
    _bound_text(subject.get("origin"), "subject.origin")
    version = subject.get("subjectVersion")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > _MAX_SAFE_INTEGER:
        _fail("ANCHOR_MALFORMED", "subject.subjectVersion must be a positive integer")

    blinding_nonce = decode_base64url(record["blindingNonce"], "blindingNonce")
    if len(blinding_nonce) != BLINDING_NONCE_BYTES:
        _fail("ANCHOR_MALFORMED", f"blindingNonce is {len(blinding_nonce)} bytes; it is exactly {BLINDING_NONCE_BYTES}")
    request_nonce = decode_base64url(record["requestNonce"], "requestNonce")
    if len(request_nonce) < MIN_REQUEST_NONCE_BYTES:
        _fail("ANCHOR_MALFORMED", f"requestNonce is {len(request_nonce)} bytes; at least {MIN_REQUEST_NONCE_BYTES} are required")

    if record["status"] == "ANCHORED":
        receipt = record["receipt"]
        if not _is_object(receipt):
            _fail("ANCHOR_MALFORMED", "an ANCHORED record must carry a receipt")
        receipt_unknown = [member for member in receipt.keys() if member not in _RECEIPT_MEMBERS]
        if receipt_unknown:
            _fail("ANCHOR_MALFORMED", f"receipt carries {', '.join(receipt_unknown)}; it holds exactly kind, token")
        if receipt.get("kind") != RECEIPT_KIND:
            _fail("ANCHOR_MALFORMED", f'receipt.kind must be "{RECEIPT_KIND}"')
        if not isinstance(receipt.get("token"), str) or receipt["token"] == "":
            _fail("ANCHOR_MALFORMED", "receipt.token is required")
    elif record["receipt"] is not None:
        _fail("ANCHOR_MALFORMED", f"a {record['status']} record must carry receipt: null")

    return {"blindingNonce": blinding_nonce, "requestNonce": request_nonce}


# ── Reading an RFC 3161 TimeStampToken (maintained parser, no verification) ─

def read_timestamp_token(token: Any) -> dict:
    der = token if isinstance(token, (bytes, bytearray)) else decode_base64(token, "receipt.token")
    try:
        content_info = cms.ContentInfo.load(bytes(der), strict=True)
        if content_info["content_type"].native != "signed_data":
            _fail("ANCHOR_RECEIPT_MALFORMED", "the token is not a CMS SignedData")
        signed_data = content_info["content"]
        encap = signed_data["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            _fail("ANCHOR_RECEIPT_MALFORMED", "the encapsulated content is not a TSTInfo")
        tst_der = encap["content"].contents  # the OCTET STRING's raw content octets
        tst = tsp.TSTInfo.load(bytes(tst_der), strict=True)
        # Force a full parse so a corrupted body refuses here, not lazily later.
        tst.native
        policy_oid = tst["policy"].dotted
        imprint = tst["message_imprint"]
        algorithm_oid = imprint["hash_algorithm"]["algorithm"].dotted
        hashed_message = imprint["hashed_message"].native
        nonce = None
        if tst["nonce"].native is not None:
            nonce = _unsigned(tst["nonce"].contents)
        gen_time = tst["gen_time"].native  # datetime, UTC
        fraction = f".{gen_time.microsecond:06d}".rstrip("0") if gen_time.microsecond else ""
        iso = gen_time.strftime("%Y-%m-%dT%H:%M:%S") + fraction + "Z"
        gen_time_canonical = canonical_timestamp(iso)
    except AnchorError:
        raise
    except Exception as error:  # asn1crypto raises ValueError and friends
        _fail("ANCHOR_RECEIPT_MALFORMED", f"receipt.token cannot be fully read: {error}")
    return {
        "policyOid": policy_oid,
        "messageImprint": {
            "algorithmOid": algorithm_oid,
            "algorithm": _IMPRINT_ALGORITHMS.get(algorithm_oid),
            "hash": hashed_message,
        },
        "nonce": nonce,
        "genTime": gen_time_canonical,
    }


# ── Verification — half one ─────────────────────────────────────────────────

def verify_anchor_binding(record: Any, subject: Any) -> dict:
    nonces = validate_anchor_record(record)
    if record["status"] != "ANCHORED":
        _fail("ANCHOR_NOT_PRESENT", f"this anchor is {record['status']}")
    material = subject_material(record["subject"]["kind"], subject)
    if material["origin"] != record["subject"]["origin"]:
        _fail("ANCHOR_MALFORMED", f'this record names origin "{record["subject"]["origin"]}"; the subject is from "{material["origin"]}"')
    if material["subjectVersion"] != record["subject"]["subjectVersion"]:
        _fail("ANCHOR_MALFORMED", f"this record names version {record['subject']['subjectVersion']}; the subject is version {material['subjectVersion']}")

    imprint = anchor_imprint(record["subject"]["kind"], nonces["blindingNonce"], subject)
    token = read_timestamp_token(record["receipt"]["token"])
    if token["messageImprint"]["algorithm"] is None:
        _fail("ANCHOR_SUITE_UNSUPPORTED", f"the token's messageImprint uses {token['messageImprint']['algorithmOid']}")
    if token["messageImprint"]["hash"] != imprint:
        _fail("ANCHOR_BINDING_MISMATCH", "the token witnesses a different imprint than this subject and blinding nonce produce")
    if token["nonce"] is None:
        _fail("ANCHOR_NONCE_MISMATCH", "the token carries no nonce; this record names one")
    if token["nonce"] != _unsigned(nonces["requestNonce"]):
        _fail("ANCHOR_NONCE_MISMATCH", "the token answers a different request than this record names")

    return {
        "subject": dict(record["subject"]),
        "trustDomain": record["trustDomain"],
        "anchorId": record["anchorId"],
        "imprint": imprint.hex(),
        "genTime": token["genTime"],
        "policyOid": token["policyOid"],
        "authorityVerified": False,
    }
