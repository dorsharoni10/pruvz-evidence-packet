"""Append-only evidence log, format version 1 — independent Python implementation.

Implemented from docs/EVIDENCE-LOG.md (PRUVZ-97): RFC 6962 / RFC 9162 tree
composition over domain-separated leaves, signed checkpoints, and the
stateful acceptance rules that turn fork, rollback and stale presentation
into refusals.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from .canonical import canonical_timestamp, canonicalize, CommitmentError
from .registry import SUITES, TrustRegistryError, decode_base64url, load_public_key, signature_verifies

EVIDENCE_LOG_FORMAT_VERSION = "1"
LEAF_ENVELOPE_VERSION = "1"
LEAF_DOMAIN_TAG = "pruvz.ai/evidence-log-leaf"
CHECKPOINT_DOMAIN_TAG = "pruvz.ai/log-checkpoint"
_SEPARATOR = "\u0000"
LEAF_HASH_PREFIX = b"\x00"
NODE_HASH_PREFIX = b"\x01"
ASSURANCE_PROFILES = ("PRE_CUSTOMER_DEFAULT", "CUSTOMER_PRODUCTION")
_MAX_BOUND_TEXT_LENGTH = 512
_MAX_SAFE_INTEGER = 9007199254740991
_HEX = re.compile(r"^[0-9a-f]{64}$")
_ROOT_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")


class EvidenceLogError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise EvidenceLogError(code, message)


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _canonical_bytes(document: Any, context: str) -> bytes:
    try:
        return canonicalize(document)
    except CommitmentError as error:
        _fail("LOG_MALFORMED", f"{context} cannot be canonicalized: {error}")


def _sha256(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _hash_from_hex(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or _HEX.match(value) is None:
        _fail("LOG_MALFORMED", f"{field} must be 64 lowercase hex digits of SHA-256")
    return bytes.fromhex(value)


def _decode_signature(value: Any, field: str) -> bytes:
    try:
        return decode_base64url(value, field, "MALFORMED_SIGNATURE")
    except TrustRegistryError as error:
        _fail("MALFORMED_SIGNATURE", str(error))


def _bound_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or value == "":
        _fail("LOG_MALFORMED", f"{field} is required")
    if len(value) > _MAX_BOUND_TEXT_LENGTH:
        _fail("LOG_MALFORMED", f"{field} must not exceed {_MAX_BOUND_TEXT_LENGTH} characters")
    if _PRINTABLE_ASCII.match(value) is None:
        _fail("LOG_MALFORMED", f"{field} must be printable ASCII")
    return value


def _safe_positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > _MAX_SAFE_INTEGER:
        _fail("LOG_MALFORMED", f"{field} must be an integer between 1 and {_MAX_SAFE_INTEGER}")
    return value


def require_supported(format_version: Any) -> None:
    if format_version != EVIDENCE_LOG_FORMAT_VERSION:
        shown = "(none)" if format_version is None else f'"{format_version}"'
        _fail("UNKNOWN_LOG_VERSION", f"Unknown evidence-log version {shown}.")


# ── Leaf encoding ───────────────────────────────────────────────────────────

def leaf_input(seal: Any) -> bytes:
    if not _is_object(seal) or not _is_object(seal.get("envelope")):
        _fail("LOG_MALFORMED", "a leaf must be { envelope, signature }")
    if seal["envelope"].get("version") != LEAF_ENVELOPE_VERSION:
        _fail("LOG_MALFORMED", f"a leaf carries an envelope of version {LEAF_ENVELOPE_VERSION}")
    signature = _decode_signature(seal.get("signature"), "seal.signature")
    suite_id = (seal["envelope"].get("signer") or {}).get("suite") if _is_object(seal["envelope"].get("signer")) else None
    suite = SUITES.get(suite_id) if isinstance(suite_id, str) else None
    if suite is not None and len(signature) != suite["signatureLength"]:
        _fail("MALFORMED_SIGNATURE", f"seal.signature is {len(signature)} bytes")
    unknown = [member for member in seal.keys() if member not in ("envelope", "signature")]
    if unknown:
        _fail("LOG_MALFORMED", f"a leaf holds exactly envelope and signature; got {', '.join(unknown)}")
    header = _SEPARATOR.join([LEAF_DOMAIN_TAG, EVIDENCE_LOG_FORMAT_VERSION, ""])
    return header.encode("utf-8") + _canonical_bytes(seal, "a leaf")


def leaf_hash_of(data: bytes) -> bytes:
    return _sha256(LEAF_HASH_PREFIX, data)


def seal_leaf_hash(seal: Any) -> str:
    return leaf_hash_of(leaf_input(seal)).hex()


# ── Tree composition (RFC 6962 §2.1) ────────────────────────────────────────

def empty_tree_hash() -> str:
    return _sha256().hex()


def _node(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_HASH_PREFIX, left, right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _leaf_buffers(leaf_hashes: Any, field: str) -> list:
    if not isinstance(leaf_hashes, list):
        _fail("LOG_MALFORMED", f"{field} must be an array of leaf hashes")
    return [_hash_from_hex(value, f"{field}[{index}]") for index, value in enumerate(leaf_hashes)]


def _head(hashes: list, lo: int, hi: int) -> bytes:
    n = hi - lo
    if n == 1:
        return hashes[lo]
    k = _split(n)
    return _node(_head(hashes, lo, lo + k), _head(hashes, lo + k, hi))


def tree_head(leaf_hashes: Any) -> str:
    hashes = _leaf_buffers(leaf_hashes, "leafHashes")
    if len(hashes) == 0:
        return empty_tree_hash()
    return _head(hashes, 0, len(hashes)).hex()


def verify_inclusion(leaf_hash: Any, leaf_index: Any, tree_size: Any, path: Any, root_hash: Any) -> None:
    leaf = _hash_from_hex(leaf_hash, "leafHash")
    root = _hash_from_hex(root_hash, "rootHash")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0:
        _fail("LOG_MALFORMED", "leafIndex must be a non-negative integer")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 1:
        _fail("LOG_MALFORMED", "treeSize must be a positive integer")
    if not isinstance(path, list):
        _fail("LOG_MALFORMED", "path must be an array of node hashes")
    nodes = [_hash_from_hex(value, f"path[{index}]") for index, value in enumerate(path)]

    if leaf_index >= tree_size:
        _fail("INCLUSION_PROOF_INVALID", f"leaf index {leaf_index} does not exist in a tree of {tree_size} leaves")

    fn, sn, r = leaf_index, tree_size - 1, leaf
    for p in nodes:
        if sn == 0:
            _fail("INCLUSION_PROOF_INVALID", "the path is longer than the tree is deep")
        if fn % 2 == 1 or fn == sn:
            r = _node(p, r)
            if fn % 2 == 0:
                while fn != 0 and fn % 2 == 0:
                    fn //= 2
                    sn //= 2
        else:
            r = _node(r, p)
        fn //= 2
        sn //= 2
    if sn != 0:
        _fail("INCLUSION_PROOF_INVALID", "the path is shorter than the tree is deep")
    if r != root:
        _fail("INCLUSION_PROOF_INVALID", "the path does not lead this leaf to this root")


def verify_consistency(from_size: Any, from_root_hash: Any, to_size: Any, to_root_hash: Any, proof: Any) -> None:
    from_root = _hash_from_hex(from_root_hash, "fromRootHash")
    to_root = _hash_from_hex(to_root_hash, "toRootHash")
    if not isinstance(from_size, int) or isinstance(from_size, bool) or from_size < 1:
        _fail("LOG_MALFORMED", "fromSize must be a positive integer")
    if not isinstance(to_size, int) or isinstance(to_size, bool) or to_size < 1:
        _fail("LOG_MALFORMED", "toSize must be a positive integer")
    if not isinstance(proof, list):
        _fail("LOG_MALFORMED", "proof must be an array of node hashes")
    nodes = [_hash_from_hex(value, f"proof[{index}]") for index, value in enumerate(proof)]

    if from_size > to_size:
        _fail("CONSISTENCY_PROOF_INVALID", f"a tree of {to_size} leaves cannot extend a tree of {from_size}")
    if from_size == to_size:
        if len(nodes) != 0:
            _fail("CONSISTENCY_PROOF_INVALID", "equal sizes take an empty proof")
        if from_root != to_root:
            _fail("CONSISTENCY_PROOF_INVALID", "two heads at one size disagree — the tree was altered in place")
        return

    if from_size & (from_size - 1) == 0:
        nodes = [from_root] + nodes
    if len(nodes) == 0:
        _fail("CONSISTENCY_PROOF_INVALID", "the proof is empty")

    fn, sn = from_size - 1, to_size - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2

    fr = sr = nodes[0]
    for c in nodes[1:]:
        if sn == 0:
            _fail("CONSISTENCY_PROOF_INVALID", "the proof is longer than the new tree is deep")
        if fn % 2 == 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if fn % 2 == 0:
                while fn != 0 and fn % 2 == 0:
                    fn //= 2
                    sn //= 2
        else:
            sr = _node(sr, c)
        fn //= 2
        sn //= 2

    if sn != 0:
        _fail("CONSISTENCY_PROOF_INVALID", "the proof is shorter than the new tree is deep")
    if fr != from_root:
        _fail("CONSISTENCY_PROOF_INVALID", "the proof does not reproduce the old head")
    if sr != to_root:
        _fail("CONSISTENCY_PROOF_INVALID", "the proof does not reproduce the new head")


# ── Checkpoints ─────────────────────────────────────────────────────────────

_CHECKPOINT_MEMBERS = (
    "assuranceProfile",
    "checkpointSequence",
    "issuedAt",
    "origin",
    "rootHash",
    "signer",
    "treeSize",
    "version",
)
_SIGNER_MEMBERS = ("keyId", "provider", "suite")


def validate_checkpoint_document(document: Any) -> dict:
    if not _is_object(document):
        _fail("LOG_MALFORMED", "a checkpoint must be an object")
    require_supported(document.get("version"))
    unknown = [member for member in document.keys() if member not in _CHECKPOINT_MEMBERS]
    if unknown:
        _fail("LOG_MALFORMED", f"a checkpoint carries {', '.join(unknown)}; the member set is closed")
    missing = [member for member in _CHECKPOINT_MEMBERS if member not in document]
    if missing:
        _fail("LOG_MALFORMED", f"a checkpoint is missing {', '.join(missing)}")
    if document["assuranceProfile"] not in ASSURANCE_PROFILES:
        _fail("LOG_MALFORMED", f"assuranceProfile must be one of {', '.join(ASSURANCE_PROFILES)}")
    _safe_positive_integer(document["checkpointSequence"], "checkpointSequence")
    _safe_positive_integer(document["treeSize"], "treeSize")
    _bound_text(document["origin"], "origin")
    if not isinstance(document["rootHash"], str) or _ROOT_HASH.match(document["rootHash"]) is None:
        _fail("LOG_MALFORMED", 'rootHash must be "sha256:" then 64 lowercase hex digits')
    issued_at_canonical = None
    if isinstance(document["issuedAt"], str):
        try:
            issued_at_canonical = canonical_timestamp(document["issuedAt"])
        except CommitmentError:
            issued_at_canonical = None
    if issued_at_canonical != document["issuedAt"]:
        _fail("LOG_MALFORMED", "issuedAt must be a canonical UTC timestamp")
    signer = document["signer"]
    if not _is_object(signer):
        _fail("LOG_MALFORMED", "signer must be an object")
    signer_unknown = [member for member in signer.keys() if member not in _SIGNER_MEMBERS]
    if signer_unknown:
        _fail("LOG_MALFORMED", f"signer carries {', '.join(signer_unknown)}")
    _bound_text(signer.get("keyId"), "signer.keyId")
    _bound_text(signer.get("provider"), "signer.provider")
    if not isinstance(signer.get("suite"), str) or signer["suite"] not in SUITES:
        _fail("LOG_MALFORMED", f'signer.suite "{signer.get("suite")}" is not a suite this contract defines')
    return document


def checkpoint_signing_input(document: Any) -> bytes:
    validate_checkpoint_document(document)
    header = _SEPARATOR.join([CHECKPOINT_DOMAIN_TAG, document["version"], ""])
    return header.encode("utf-8") + _canonical_bytes(document, "a checkpoint")


def verify_checkpoint(checkpoint: Any, signature: Any, jwk: Any) -> None:
    validate_checkpoint_document(checkpoint)
    suite = SUITES[checkpoint["signer"]["suite"]]
    signature_bytes = _decode_signature(signature, "signature")
    if len(signature_bytes) != suite["signatureLength"]:
        _fail("MALFORMED_SIGNATURE", f"signature is {len(signature_bytes)} bytes")
    if not _is_object(jwk):
        _fail("INVALID_PUBLIC_KEY", "jwk must be a public JSON Web Key object")
    try:
        load_public_key(jwk, checkpoint["signer"]["suite"])
    except TrustRegistryError:
        _fail("INVALID_PUBLIC_KEY", "jwk is not a valid public key")
    if not signature_verifies(checkpoint_signing_input(checkpoint), jwk, checkpoint["signer"]["suite"], signature_bytes):
        _fail("CHECKPOINT_SIGNATURE_INVALID", "the signature over this checkpoint does not verify under this key")


def accept_checkpoint(accepted: Any, candidate: Any, consistency_proof: Any = None) -> dict:
    validate_checkpoint_document(candidate)
    state = {
        "checkpointSequence": candidate["checkpointSequence"],
        "origin": candidate["origin"],
        "rootHash": candidate["rootHash"],
        "treeSize": candidate["treeSize"],
    }
    if accepted is None:
        return state
    if not _is_object(accepted):
        _fail("LOG_MALFORMED", "accepted must be the state a previous acceptance returned")
    _bound_text(accepted.get("origin"), "accepted.origin")
    _safe_positive_integer(accepted.get("checkpointSequence"), "accepted.checkpointSequence")
    _safe_positive_integer(accepted.get("treeSize"), "accepted.treeSize")
    if not isinstance(accepted.get("rootHash"), str) or _ROOT_HASH.match(accepted["rootHash"]) is None:
        _fail("LOG_MALFORMED", 'accepted.rootHash must be "sha256:" then 64 lowercase hex digits')

    if candidate["origin"] != accepted["origin"]:
        _fail("CHECKPOINT_ORIGIN_MISMATCH", f'this checkpoint is from log "{candidate["origin"]}", not "{accepted["origin"]}"')
    if candidate["checkpointSequence"] < accepted["checkpointSequence"]:
        _fail("CHECKPOINT_STALE", f"checkpoint {candidate['checkpointSequence']} is older than the already accepted {accepted['checkpointSequence']}")
    if candidate["checkpointSequence"] == accepted["checkpointSequence"]:
        if candidate["treeSize"] == accepted["treeSize"] and candidate["rootHash"] == accepted["rootHash"]:
            return dict(state)
        _fail("CHECKPOINT_FORK", f"two checkpoints numbered {candidate['checkpointSequence']} disagree — the log presented two histories")
    if candidate["treeSize"] < accepted["treeSize"]:
        _fail("CHECKPOINT_ROLLBACK", f"checkpoint {candidate['checkpointSequence']} covers {candidate['treeSize']} leaves but {accepted['checkpointSequence']} already covered {accepted['treeSize']}")
    if candidate["treeSize"] == accepted["treeSize"]:
        if candidate["rootHash"] != accepted["rootHash"]:
            _fail("CHECKPOINT_FORK", "a later checkpoint at the same tree size names a different head")
        return state
    verify_consistency(
        accepted["treeSize"],
        accepted["rootHash"][len("sha256:"):],
        candidate["treeSize"],
        candidate["rootHash"][len("sha256:"):],
        consistency_proof if consistency_proof is not None else [],
    )
    return state
