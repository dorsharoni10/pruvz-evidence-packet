"""Public Trust Registry, format version 1 — independent Python implementation.

Implemented from docs/TRUST-REGISTRY.md (PRUVZ-97). ECDSA verification comes
from the maintained ``cryptography`` library; nothing cryptographic is
implemented here. Signatures travel in the fixed-width IEEE P1363 form
(r || s) and are converted to the DER form the library verifies.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .canonical import CommitmentError, canonical_timestamp, canonicalize

TRUST_REGISTRY_FORMAT_VERSION = "1"
SEAL_ENVELOPE_VERSION = "1"

_REGISTRY_DOMAIN_TAG = "pruvz.ai/trust-registry"
_SEAL_DOMAIN_TAG = "pruvz.ai/evidence-signature"
_SEPARATOR = "\u0000"

KEY_USES = ("trust-root", "evidence-signing")
KEY_STATUSES = ("ACTIVE", "RETIRED", "REVOKED")

SUITES = {
    "ES256": {"crv": "P-256", "hash": "sha256", "coordinateLength": 32, "signatureLength": 64},
    "ES384": {"crv": "P-384", "hash": "sha384", "coordinateLength": 48, "signatureLength": 96},
}

_JWK_MEMBERS = ("crv", "kty", "x", "y")
_KEY_MEMBERS = (
    "keyId",
    "predecessorKeyId",
    "provider",
    "publicKey",
    "retiredAtUtc",
    "revocationReason",
    "revokedAtUtc",
    "status",
    "suite",
    "thumbprint",
    "use",
    "validFromUtc",
)
_MANIFEST_MEMBERS = ("formatVersion", "issuedAtUtc", "issuer", "keys", "previous", "registryVersion")
_MAX_TEXT_LENGTH = 512
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class TrustRegistryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise TrustRegistryError(code, message)


def _is_object(value: Any) -> bool:
    return isinstance(value, dict)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or value == "":
        _fail("INVALID_MANIFEST", f"{field} is required and must be a non-empty string")
    if len(value) > _MAX_TEXT_LENGTH:
        _fail("TEXT_OUT_OF_BOUNDS", f"{field} must not exceed {_MAX_TEXT_LENGTH} characters")
    return value


def _optional_text(value: Any, field: str) -> Optional[str]:
    return None if value is None else _text(value, field)


def _key_id_text(value: Any, field: str) -> str:
    key_id = _text(value, field)
    if any(not (0x20 <= ord(char) <= 0x7E) for char in key_id):
        _fail("INVALID_MANIFEST", f"{field} must be printable ASCII")
    return key_id


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64url(value: Any, field: str, code: str = "INVALID_SIGNATURE_ENCODING") -> bytes:
    if not isinstance(value, str) or value == "":
        _fail(code, f"{field} is required and must be unpadded base64url")
    if re.match(r"^[A-Za-z0-9_-]+$", value) is None:
        _fail(code, f"{field} is not unpadded base64url")
    padded = value + "=" * (-len(value) % 4)
    try:
        data = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        _fail(code, f"{field} is not unpadded base64url")
    # Canonical: the decoded bytes must re-encode to exactly the text received,
    # so a signature has one transported spelling and only one.
    if base64url_encode(data) != value:
        _fail(code, f"{field} is not a canonical unpadded base64url encoding")
    return data


def comparable_instant(value: Any, field: str) -> str:
    try:
        canonical = canonical_timestamp(value)
    except CommitmentError as error:
        _fail("INVALID_MANIFEST", f"{field}: {error}")
    match = re.match(r"^(.+?)(?:\.(\d+))?Z$", canonical)
    seconds, fraction = match.group(1), match.group(2) or ""
    return f"{seconds}.{fraction.ljust(9, '0')}"


def require_public_jwk(jwk: Any, field: str) -> dict:
    if not _is_object(jwk):
        _fail("INVALID_PUBLIC_KEY", f"{field} must be a JSON Web Key object")
    if "d" in jwk:
        _fail("PRIVATE_KEY_MATERIAL", f"{field} carries a private component (d)")
    unknown = [member for member in jwk.keys() if member not in _JWK_MEMBERS]
    if unknown:
        _fail("INVALID_PUBLIC_KEY", f"{field} carries {', '.join(unknown)}")
    missing = [member for member in _JWK_MEMBERS if member not in jwk]
    if missing:
        _fail("INVALID_PUBLIC_KEY", f"{field} is missing {', '.join(missing)}")
    if jwk["kty"] != "EC":
        _fail("INVALID_PUBLIC_KEY", f'{field}.kty must be "EC"')
    suite = next((candidate for candidate in SUITES.values() if candidate["crv"] == jwk["crv"]), None)
    if suite is None:
        _fail("INVALID_PUBLIC_KEY", f'{field}.crv "{jwk["crv"]}" is not a curve this registry format defines')
    for coordinate in ("x", "y"):
        data = decode_base64url(jwk[coordinate], f"{field}.{coordinate}", "INVALID_PUBLIC_KEY")
        if len(data) != suite["coordinateLength"]:
            _fail(
                "INVALID_PUBLIC_KEY",
                f"{field}.{coordinate} is {len(data)} bytes; curve {jwk['crv']} requires exactly "
                f"{suite['coordinateLength']}, zero-padded (RFC 7518)",
            )
    return jwk


def jwk_thumbprint(jwk: Any) -> str:
    key = require_public_jwk(jwk, "publicKey")
    canonical = canonicalize({"crv": key["crv"], "kty": key["kty"], "x": key["x"], "y": key["y"]})
    return "sha256:" + base64url_encode(hashlib.sha256(canonical).digest())


def require_supported(format_version: Any) -> None:
    if format_version != TRUST_REGISTRY_FORMAT_VERSION:
        shown = "(none)" if format_version is None else f'"{format_version}"'
        _fail("UNKNOWN_REGISTRY_FORMAT_VERSION", f"Unknown trust-registry format version {shown}.")


def manifest_input(manifest: Any) -> bytes:
    if not _is_object(manifest):
        _fail("INVALID_MANIFEST", "manifest must be an object")
    require_supported(manifest.get("formatVersion"))
    header = _SEPARATOR.join([_REGISTRY_DOMAIN_TAG, TRUST_REGISTRY_FORMAT_VERSION, ""])
    return header.encode("utf-8") + canonicalize(manifest)


def manifest_digest(manifest: Any) -> str:
    return "sha256:" + hashlib.sha256(manifest_input(manifest)).hexdigest()


def key_state_at(key: dict, instant: Any) -> str:
    when = comparable_instant(instant, "instant")
    if key["revokedAtUtc"] is not None and when >= comparable_instant(key["revokedAtUtc"], "revokedAtUtc"):
        return "REVOKED"
    if key["retiredAtUtc"] is not None and when >= comparable_instant(key["retiredAtUtc"], "retiredAtUtc"):
        return "RETIRED"
    if when < comparable_instant(key["validFromUtc"], "validFromUtc"):
        return "NOT_YET_VALID"
    return "ACTIVE"


def _require_exact_members(value: dict, expected: tuple, field: str, code: str = "INVALID_MANIFEST") -> None:
    declared = list(value.keys())
    unknown = [member for member in declared if member not in expected]
    missing = [member for member in expected if member not in declared]
    if unknown or missing:
        _fail(code, f"{field} must declare exactly {', '.join(expected)}"
              + (f"; unexpected: {', '.join(unknown)}" if unknown else "")
              + (f"; missing: {', '.join(missing)}" if missing else ""))


def _validate_key(raw: Any, field: str, issued_at_utc: str) -> dict:
    if not _is_object(raw):
        _fail("INVALID_MANIFEST", f"{field} must be an object")
    _require_exact_members(raw, _KEY_MEMBERS, field)
    key = {
        "keyId": _key_id_text(raw["keyId"], f"{field}.keyId"),
        "predecessorKeyId": None if raw["predecessorKeyId"] is None else _key_id_text(raw["predecessorKeyId"], f"{field}.predecessorKeyId"),
        "provider": _text(raw["provider"], f"{field}.provider"),
        "publicKey": require_public_jwk(raw["publicKey"], f"{field}.publicKey"),
        "retiredAtUtc": _optional_text(raw["retiredAtUtc"], f"{field}.retiredAtUtc"),
        "revocationReason": _optional_text(raw["revocationReason"], f"{field}.revocationReason"),
        "revokedAtUtc": _optional_text(raw["revokedAtUtc"], f"{field}.revokedAtUtc"),
        "status": raw["status"],
        "suite": raw["suite"],
        "thumbprint": _text(raw["thumbprint"], f"{field}.thumbprint"),
        "use": raw["use"],
        "validFromUtc": _text(raw["validFromUtc"], f"{field}.validFromUtc"),
    }
    if key["use"] not in KEY_USES:
        _fail("UNKNOWN_KEY_USE", f"{field}.use must be one of {', '.join(KEY_USES)}")
    if key["suite"] not in SUITES:
        _fail("UNKNOWN_SUITE", f"{field}.suite must be one of {', '.join(SUITES)}")
    if SUITES[key["suite"]]["crv"] != key["publicKey"]["crv"]:
        _fail("INVALID_PUBLIC_KEY", f"{field}: suite {key['suite']} signs on another curve than the key")
    if key["status"] not in KEY_STATUSES:
        _fail("INVALID_MANIFEST", f"{field}.status must be one of {', '.join(KEY_STATUSES)}")
    computed = jwk_thumbprint(key["publicKey"])
    if computed != key["thumbprint"]:
        _fail("THUMBPRINT_MISMATCH", f"{field}.thumbprint is {key['thumbprint']} but the key thumbprints to {computed}")
    if key["revocationReason"] is not None and key["revokedAtUtc"] is None:
        _fail("INVALID_MANIFEST", f"{field}.revocationReason is set on a key that is not revoked")
    if comparable_instant(key["validFromUtc"], f"{field}.validFromUtc") > comparable_instant(issued_at_utc, "manifest.issuedAtUtc"):
        _fail("KEY_NOT_YET_VALID", f"{field}.validFromUtc is after the manifest's own issuedAtUtc")
    state_at_issue = key_state_at(key, issued_at_utc)
    if state_at_issue != key["status"]:
        _fail(
            "KEY_STATUS_INCONSISTENT",
            f"{field}.status is {key['status']}, but its own timestamps put it at {state_at_issue}",
        )
    return key


def validate_registry_document(document: Any) -> dict:
    if not _is_object(document):
        _fail("INVALID_MANIFEST", "A trust-registry document must be an object")
    _require_exact_members(document, ("attestations", "manifest", "signatures"), "The document")
    raw = document["manifest"]
    if not _is_object(raw):
        _fail("INVALID_MANIFEST", "document.manifest must be an object")
    _require_exact_members(raw, _MANIFEST_MEMBERS, "manifest")
    require_supported(raw.get("formatVersion"))
    if not isinstance(raw["registryVersion"], int) or isinstance(raw["registryVersion"], bool) or raw["registryVersion"] < 1:
        _fail("INVALID_MANIFEST", "manifest.registryVersion must be an integer of at least 1")
    issued_at_utc = _text(raw["issuedAtUtc"], "manifest.issuedAtUtc")
    comparable_instant(issued_at_utc, "manifest.issuedAtUtc")

    if (raw["registryVersion"] == 1) != (raw["previous"] is None):
        _fail(
            "REGISTRY_CHAIN_BROKEN",
            "The first manifest has no predecessor, so manifest.previous must be null"
            if raw["registryVersion"] == 1
            else "Only the first manifest may have a null manifest.previous",
        )

    previous = None
    if raw["previous"] is not None:
        if not _is_object(raw["previous"]):
            _fail("INVALID_MANIFEST", "manifest.previous must be an object or null")
        _require_exact_members(raw["previous"], ("digest", "registryVersion"), "manifest.previous")
        previous = {
            "digest": _text(raw["previous"]["digest"], "manifest.previous.digest"),
            "registryVersion": raw["previous"]["registryVersion"],
        }
        if (
            not isinstance(previous["registryVersion"], int)
            or isinstance(previous["registryVersion"], bool)
            or previous["registryVersion"] != raw["registryVersion"] - 1
        ):
            _fail("REGISTRY_CHAIN_BROKEN", f"manifest.previous.registryVersion must be {raw['registryVersion'] - 1}")
        if _DIGEST.match(previous["digest"]) is None:
            _fail("INVALID_MANIFEST", 'manifest.previous.digest must be "sha256:" and 64 lowercase hex')

    if not isinstance(raw["keys"], list) or len(raw["keys"]) == 0:
        _fail("INVALID_MANIFEST", "manifest.keys must be a non-empty array")

    manifest = {
        "formatVersion": raw["formatVersion"],
        "issuedAtUtc": issued_at_utc,
        "issuer": _text(raw["issuer"], "manifest.issuer"),
        "keys": [_validate_key(key, f"manifest.keys[{index}]", issued_at_utc) for index, key in enumerate(raw["keys"])],
        "previous": previous,
        "registryVersion": raw["registryVersion"],
    }

    ids = set()
    for key in manifest["keys"]:
        if key["keyId"] in ids:
            _fail("DUPLICATE_KEY_ID", f'manifest.keys declares "{key["keyId"]}" more than once')
        ids.add(key["keyId"])
    for key in manifest["keys"]:
        if key["predecessorKeyId"] is not None and key["predecessorKeyId"] not in ids:
            _fail("INVALID_MANIFEST", f'"{key["keyId"]}" names an undeclared predecessor')

    if not isinstance(document["signatures"], list) or len(document["signatures"]) == 0:
        _fail("INVALID_MANIFEST", "document.signatures must be a non-empty array")

    signatures = []
    for index, entry in enumerate(document["signatures"]):
        field = f"signatures[{index}]"
        if not _is_object(entry):
            _fail("INVALID_MANIFEST", f"{field} must be an object")
        _require_exact_members(entry, ("keyId", "signature", "suite"), field)
        key_id = _key_id_text(entry["keyId"], f"{field}.keyId")
        signer = next((key for key in manifest["keys"] if key["keyId"] == key_id), None)
        if signer is None:
            _fail("UNKNOWN_SIGNER", f'{field} names key "{key_id}", which the manifest it signs does not declare')
        if signer["use"] != "trust-root":
            _fail("UNKNOWN_SIGNER", f'{field} is made by "{key_id}", whose use is {signer["use"]}')
        if entry["suite"] != signer["suite"]:
            _fail("INVALID_MANIFEST", f"{field}.suite is {entry['suite']} but the key is declared as {signer['suite']}")
        signature = decode_base64url(entry["signature"], f"{field}.signature")
        if len(signature) != SUITES[signer["suite"]]["signatureLength"]:
            _fail("MALFORMED_SIGNATURE", f"{field}.signature is {len(signature)} bytes")
        signatures.append({"keyId": key_id, "signature": signature, "signer": signer, "suite": entry["suite"]})

    signer_ids = set()
    for entry in signatures:
        if entry["keyId"] in signer_ids:
            _fail("INVALID_MANIFEST", f'document.signatures names "{entry["keyId"]}" more than once')
        signer_ids.add(entry["keyId"])

    if document["attestations"] is not None and not _is_object(document["attestations"]):
        _fail("INVALID_MANIFEST", "document.attestations must be an object or null")

    return {"attestations": document["attestations"], "manifest": manifest, "signatures": signatures}


def load_public_key(jwk: Any, suite: str):
    """Builds the EC public key a JWK describes, refusing one the platform
    cannot build (a coordinate off the curve, a malformed encoding)."""
    try:
        curve = ec.SECP256R1() if SUITES[suite]["crv"] == "P-256" else ec.SECP384R1()
        x = int.from_bytes(decode_base64url(jwk["x"], "jwk.x", "INVALID_PUBLIC_KEY"), "big")
        y = int.from_bytes(decode_base64url(jwk["y"], "jwk.y", "INVALID_PUBLIC_KEY"), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    except TrustRegistryError:
        raise
    except (ValueError, TypeError, KeyError) as error:
        _fail("INVALID_PUBLIC_KEY", f"jwk is not a valid public key: {error}")


def signature_verifies(data: bytes, jwk: dict, suite: str, signature: bytes) -> bool:
    """One ECDSA verification through the maintained library; False, never a throw."""
    try:
        public_key = load_public_key(jwk, suite)
        coordinate_length = SUITES[suite]["coordinateLength"]
        r = int.from_bytes(signature[:coordinate_length], "big")
        s = int.from_bytes(signature[coordinate_length:], "big")
        algorithm = hashes.SHA256() if SUITES[suite]["hash"] == "sha256" else hashes.SHA384()
        public_key.verify(encode_dss_signature(r, s), data, ec.ECDSA(algorithm))
        return True
    except (InvalidSignature, TrustRegistryError, ValueError):
        return False


def _require_pin(pin: Any) -> None:
    if not _is_object(pin) or not isinstance(pin.get("issuer"), str) or not isinstance(pin.get("root"), str):
        _fail("NO_TRUST_ANCHOR", "A pinned root { issuer, root } is required; there is no pinless mode")


def root_pin_from_manifest(document: Any) -> dict:
    validated = validate_registry_document(document)
    roots = [key for key in validated["manifest"]["keys"] if key["use"] == "trust-root" and key["status"] == "ACTIVE"]
    if len(roots) == 0:
        _fail("NO_TRUST_ANCHOR", "The manifest declares no active trust root to pin")
    if len(roots) > 1:
        _fail("AMBIGUOUS_ROOT", f"The manifest declares {len(roots)} active trust roots")
    return {"issuer": validated["manifest"]["issuer"], "root": roots[0]["thumbprint"]}


def verify_manifest(document: Any, pin: Any) -> dict:
    _require_pin(pin)
    validated = validate_registry_document(document)
    manifest = validated["manifest"]
    if manifest["issuer"] != pin["issuer"]:
        _fail("ISSUER_MISMATCH", f'The manifest is issued by "{manifest["issuer"]}", but the pin names "{pin["issuer"]}"')
    pinned = next((entry for entry in validated["signatures"] if entry["signer"]["thumbprint"] == pin["root"]), None)
    if pinned is None:
        _fail("ROOT_MISMATCH", "No signature on this manifest was made by the pinned root")
    if not signature_verifies(manifest_input(manifest), pinned["signer"]["publicKey"], pinned["suite"], pinned["signature"]):
        _fail("REGISTRY_SIGNATURE_INVALID", "The pinned root's signature does not verify over this manifest")
    return {
        "attestations": validated["attestations"],
        "digest": manifest_digest(manifest),
        "manifest": manifest,
        "rootKeyId": pinned["signer"]["keyId"],
        "rootStatus": pinned["signer"]["status"],
    }


def accept_chain(documents: Any, pin: Any, state: Any = None) -> dict:
    _require_pin(pin)
    if not isinstance(documents, list) or len(documents) == 0:
        _fail("INVALID_MANIFEST", "acceptChain requires at least one trust-registry document")
    if state is not None:
        if not _is_object(state) or not isinstance(state.get("issuer"), str) or not isinstance(state.get("root"), str):
            _fail("NO_TRUST_ANCHOR", "The verifier state must record the { issuer, root } it was established under")
        if state["issuer"] != pin["issuer"]:
            _fail("ISSUER_MISMATCH", "The verifier state was established for another issuer")
        if state["root"] != pin["root"]:
            _fail("ROOT_MISMATCH", "The verifier state was established under a different trust root")

    current = None if state is None else dict(state)
    accepted = None
    for document in documents:
        verified = verify_manifest(document, pin)
        manifest, digest = verified["manifest"], verified["digest"]
        if current is not None:
            if manifest["registryVersion"] < current["registryVersion"]:
                # History below the held watermark: verified, never current.
                continue
            if manifest["registryVersion"] == current["registryVersion"]:
                if digest != current["digest"]:
                    _fail("REGISTRY_FORK", f"Two different manifests both claim registry version {manifest['registryVersion']}")
                accepted = verified
                continue
            if manifest["registryVersion"] != current["registryVersion"] + 1:
                _fail("REGISTRY_CHAIN_BROKEN", f"Cannot step from registry version {current['registryVersion']} to {manifest['registryVersion']}")
            if (
                manifest["previous"]["registryVersion"] != current["registryVersion"]
                or manifest["previous"]["digest"] != current["digest"]
            ):
                _fail("REGISTRY_CHAIN_BROKEN", f"Registry version {manifest['registryVersion']} does not link to the held manifest")
        current = {
            "digest": digest,
            "issuer": manifest["issuer"],
            "registryVersion": manifest["registryVersion"],
            "root": pin["root"],
        }
        accepted = verified
    if accepted is None:
        _fail(
            "REGISTRY_ROLLBACK",
            f"Every served manifest is older than registry version {current['registryVersion']}, "
            "which this verifier has already accepted",
        )
    reason_codes = []
    if accepted["rootStatus"] == "REVOKED":
        reason_codes.append("ROOT_REVOKED")
    elif accepted["rootStatus"] == "RETIRED":
        reason_codes.append("ROOT_RETIRED")
    result = dict(accepted)
    result["reasonCodes"] = reason_codes
    result["state"] = current
    return result


def resolve_signing_key(manifest: dict, key_id: Any) -> tuple:
    key = next((candidate for candidate in manifest["keys"] if candidate["keyId"] == key_id), None)
    if key is None:
        return None, "UNKNOWN_KEY"
    if key["use"] != "evidence-signing":
        return key, "KEY_USE_MISMATCH"
    return key, None


def seal_signing_input(envelope: Any) -> bytes:
    if not _is_object(envelope):
        _fail("INVALID_MANIFEST", "seal.envelope must be an object")
    if envelope.get("version") != SEAL_ENVELOPE_VERSION:
        shown = "(none)" if envelope.get("version") is None else f'"{envelope.get("version")}"'
        _fail("UNKNOWN_ENVELOPE_VERSION", f"Unknown evidence-envelope version {shown}.")
    header = _SEPARATOR.join([_SEAL_DOMAIN_TAG, envelope["version"], ""])
    return header.encode("utf-8") + canonicalize(envelope)


def verify_seal(seal: Any, manifest: dict, expected_subject: Any, expected_commitment_digest: Any = None, registry_reason_codes=()) -> dict:
    if not _is_object(seal) or not _is_object(seal.get("envelope")):
        _fail("INVALID_MANIFEST", "seal must be { envelope, signature }")
    if not _is_object(manifest) or not isinstance(manifest.get("keys"), list):
        _fail("INVALID_MANIFEST", "manifest must be a verified manifest from verifyManifest/acceptChain")
    if not _is_object(expected_subject):
        _fail("INVALID_MANIFEST", "expectedSubject is required")

    envelope = seal["envelope"]
    dimensions = {
        "content": "NOT_CHECKED",
        "keyIdentity": "NOT_CHECKED",
        "keyLifecycle": "NOT_CHECKED",
        "signature": "NOT_CHECKED",
        "subject": "NOT_CHECKED",
    }
    reason_codes = list(registry_reason_codes)

    def invalid(code: str) -> dict:
        reason_codes.append(code)
        return {"dimensions": dimensions, "reasonCodes": reason_codes, "verdict": "INVALID"}

    if envelope.get("version") != SEAL_ENVELOPE_VERSION:
        return invalid("UNKNOWN_ENVELOPE_VERSION")
    signer_ref = envelope.get("signer")
    if not _is_object(signer_ref) or not isinstance(signer_ref.get("keyId"), str):
        return invalid("MALFORMED_ENVELOPE")
    key, reason = resolve_signing_key(manifest, signer_ref["keyId"])
    if reason is not None:
        return invalid(reason)
    dimensions["keyIdentity"] = "TRUSTED"
    if signer_ref.get("suite") != key["suite"]:
        return invalid("KEY_SUITE_MISMATCH")
    if signer_ref.get("provider") != key["provider"]:
        return invalid("KEY_PROVIDER_MISMATCH")

    try:
        signature = decode_base64url(seal.get("signature"), "seal.signature")
    except TrustRegistryError:
        return invalid("MALFORMED_SIGNATURE")
    if len(signature) != SUITES[key["suite"]]["signatureLength"]:
        return invalid("MALFORMED_SIGNATURE")

    try:
        signing_input = seal_signing_input(envelope)
    except (TrustRegistryError, CommitmentError):
        return invalid("MALFORMED_ENVELOPE")

    if not signature_verifies(signing_input, key["publicKey"], key["suite"], signature):
        dimensions["signature"] = "INVALID"
        return invalid("SIGNATURE_INVALID")
    dimensions["signature"] = "VALID"

    if not isinstance(envelope.get("committedAt"), str):
        return invalid("MALFORMED_ENVELOPE")
    try:
        state_when_signed = key_state_at(key, envelope["committedAt"])
    except TrustRegistryError:
        return invalid("MALFORMED_ENVELOPE")
    dimensions["keyLifecycle"] = state_when_signed
    if state_when_signed == "NOT_YET_VALID":
        return invalid("SIGNED_BEFORE_KEY_VALID")
    if state_when_signed == "REVOKED":
        return invalid("SIGNED_AFTER_REVOCATION")
    if state_when_signed == "RETIRED":
        return invalid("SIGNED_AFTER_RETIREMENT")

    weakened = "ROOT_REVOKED" in reason_codes
    if key["revokedAtUtc"] is not None:
        reason_codes.extend(["SIGNED_BEFORE_REVOCATION", "COMMITTED_AT_SELF_ASSERTED"])
        weakened = True
    elif key["retiredAtUtc"] is not None:
        reason_codes.append("KEY_RETIRED_AFTER_SIGNING")

    subject = envelope.get("subject")
    if (
        not _is_object(subject)
        or subject.get("tenantId") != expected_subject.get("tenantId")
        or subject.get("actionId") != expected_subject.get("actionId")
        or subject.get("evidenceId") != expected_subject.get("evidenceId")
        or subject.get("sequence") != expected_subject.get("sequence")
    ):
        dimensions["subject"] = "MISMATCH"
        return invalid("SUBJECT_MISMATCH")
    dimensions["subject"] = "MATCHES"

    if expected_commitment_digest is None:
        reason_codes.append("COMMITMENT_NOT_CHECKED")
        weakened = True
    elif (envelope.get("commitment") or {}).get("digest") != expected_commitment_digest:
        dimensions["content"] = "MISMATCH"
        return invalid("COMMITMENT_MISMATCH")
    else:
        dimensions["content"] = "MATCHES"

    return {"dimensions": dimensions, "reasonCodes": reason_codes, "verdict": "PARTIAL" if weakened else "VALID"}
