"""Half two of anchor verification (docs/ANCHORING.md §6) — Python.

Is the RFC 3161 timestamp token itself authentic? The CMS SignedData signature
over the TSTInfo, the signer's sole and critical timestamping purpose, the
signer's validity at the token's own genTime, and a chain ending at a root the
CALLER pinned — never an ambient trust store.

Composition only: ASN.1/CMS parsing is ``asn1crypto``; every signature and
digest verification is the maintained ``cryptography`` library (RSA PKCS#1
v1.5 and ECDSA, the algorithms real timestamp authorities sign with). The CMS
signed-attributes rules are applied per RFC 5652 §5.4: the signature covers
the DER of the signed attributes re-tagged as an explicit SET OF, and the
message-digest attribute must equal the digest of the encapsulated TSTInfo.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, List, Optional

from asn1crypto import cms, x509 as asn1x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

from .anchoring import AnchorError, decode_base64, read_timestamp_token

OID_EKU_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"

_HASHES = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha1": hashes.SHA1,
}
_DIGESTS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha1": hashlib.sha1,
}


def _fail(code: str, message: str) -> None:
    raise AnchorError(code, message)


def _token_bytes(token: Any) -> bytes:
    return decode_base64(token, "receipt.token")


def _parse_signed_data(der: bytes) -> cms.SignedData:
    try:
        content_info = cms.ContentInfo.load(der, strict=True)
    except AnchorError:
        raise
    except Exception:
        _fail("ANCHOR_RECEIPT_MALFORMED", "receipt.token is not a DER ContentInfo")
    if content_info["content_type"].native != "signed_data":
        _fail("ANCHOR_RECEIPT_MALFORMED", "receipt.token is not CMS SignedData")
    signed_data = content_info["content"]
    if signed_data["encap_content_info"]["content_type"].native != "tst_info":
        _fail("ANCHOR_RECEIPT_MALFORMED", "the signed content is not a TSTInfo")
    return signed_data


def embedded_certificates(token: Any) -> List[str]:
    """Every certificate embedded in a token, as PEM — pin candidates, never
    trusted by virtue of being embedded."""
    signed_data = _parse_signed_data(_token_bytes(token))
    pems = []
    for entry in signed_data["certificates"] or []:
        if entry.name != "certificate":
            continue
        der = entry.chosen.dump()
        loaded = x509.load_der_x509_certificate(der)
        pems.append(loaded.public_bytes(Encoding.PEM).decode("ascii"))
    return pems


def _signer_certificate(signed_data: cms.SignedData) -> asn1x509.Certificate:
    signer_infos = signed_data["signer_infos"]
    if len(signer_infos) != 1:
        _fail("ANCHOR_RECEIPT_MALFORMED", "a timestamp token carries exactly one SignerInfo")
    sid = signer_infos[0]["sid"]
    if sid.name != "issuer_and_serial_number":
        _fail("ANCHOR_RECEIPT_MALFORMED", "the SignerInfo does not identify its certificate by issuer and serial")
    issuer = sid.chosen["issuer"]
    serial = sid.chosen["serial_number"].native
    for entry in signed_data["certificates"] or []:
        if entry.name != "certificate":
            continue
        certificate = entry.chosen
        if certificate["tbs_certificate"]["serial_number"].native == serial and certificate["tbs_certificate"]["issuer"] == issuer:
            return certificate
    _fail("ANCHOR_RECEIPT_MALFORMED", "the signing certificate is not embedded in the token")


def _require_timestamping_purpose(certificate: asn1x509.Certificate) -> None:
    extension = None
    for ext in certificate["tbs_certificate"]["extensions"] or []:
        if ext["extn_id"].dotted == "2.5.29.37":
            extension = ext
            break
    if extension is None:
        _fail("ANCHOR_UNTRUSTED_AUTHORITY", "the signing certificate declares no extended key usage")
    if extension["critical"].native is not True:
        _fail("ANCHOR_UNTRUSTED_AUTHORITY", "the extended key usage of a timestamping certificate must be critical")
    try:
        purposes = [oid.dotted for oid in extension["extn_value"].parsed]
    except Exception:
        _fail("ANCHOR_RECEIPT_MALFORMED", "the extended key usage extension is not parseable")
    if len(purposes) != 1 or purposes[0] != OID_EKU_TIME_STAMPING:
        _fail(
            "ANCHOR_UNTRUSTED_AUTHORITY",
            f"the signing certificate's purposes are [{', '.join(purposes)}]; "
            "a timestamping certificate carries exactly id-kp-timeStamping",
        )


def _load_pem_roots(roots: List[str]):
    loaded = []
    for index, pem in enumerate(roots):
        match = re.search(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----", pem)
        if match is None:
            _fail("ANCHOR_MALFORMED", f"pinned root {index} is not a PEM certificate")
        loaded.append(x509.load_pem_x509_certificate(match.group(0).encode("ascii")))
    return loaded


def _verify_certificate_signature(subject: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        subject.verify_directly_issued_by(issuer)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _valid_at(certificate: x509.Certificate, instant) -> bool:
    return certificate.not_valid_before_utc <= instant <= certificate.not_valid_after_utc


def _chain_to_pinned_root(signer: x509.Certificate, embedded: List[x509.Certificate], roots: List[x509.Certificate], instant) -> bool:
    """Builds a path from the signer through the embedded certificates to a
    pinned root, verifying each signature and each certificate's validity at
    the token's own genTime. Pinned chains here are short (authority root plus
    a leaf, sometimes an intermediate); path building is by issuer match."""
    current = signer
    seen = set()
    for _ in range(len(embedded) + 2):
        if not _valid_at(current, instant):
            return False
        for root in roots:
            if current.issuer == root.subject and _verify_certificate_signature(current, root):
                return _valid_at(root, instant)
        # A pinned root presented AS the signer (self-signed) also terminates.
        for root in roots:
            if current == root:
                return True
        advanced = False
        for candidate in embedded:
            if candidate.fingerprint(hashes.SHA256()) in seen:
                continue
            if current.issuer == candidate.subject and _verify_certificate_signature(current, candidate):
                seen.add(candidate.fingerprint(hashes.SHA256()))
                current = candidate
                advanced = True
                break
        if not advanced:
            return False
    return False


def _verify_cms_signature(signed_data: cms.SignedData, signer_cert: asn1x509.Certificate) -> None:
    signer_info = signed_data["signer_infos"][0]
    digest_algorithm = signer_info["digest_algorithm"]["algorithm"].native
    if digest_algorithm not in _DIGESTS:
        _fail("ANCHOR_RECEIPT_MALFORMED", f"a digest algorithm this implementation does not read: {digest_algorithm}")
    econtent = bytes(signed_data["encap_content_info"]["content"].contents)

    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is not None and len(signed_attrs) > 0:
        # RFC 5652 §5.4: message-digest must equal the digest of the eContent,
        # and the signature covers the attributes re-tagged as SET OF.
        message_digest = None
        content_type = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest = attr["values"][0].native
            elif attr["type"].native == "content_type":
                content_type = attr["values"][0].native
        if message_digest is None or content_type != "tst_info":
            _fail("ANCHOR_SIGNATURE_INVALID", "the token's signed attributes do not bind a TSTInfo digest")
        if message_digest != _DIGESTS[digest_algorithm](econtent).digest():
            _fail("ANCHOR_SIGNATURE_INVALID", "the token's message-digest attribute does not match the TSTInfo")
        raw = signed_attrs.dump()
        signed_bytes = b"\x31" + raw[1:]
    else:
        signed_bytes = econtent

    signature = signer_info["signature"].native
    signature_algorithm = signer_info["signature_algorithm"]["algorithm"].native
    public_key = x509.load_der_x509_certificate(signer_cert.dump()).public_key()
    hash_class = _HASHES[digest_algorithm]
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if signature_algorithm == "rsassa_pss":
                params = signer_info["signature_algorithm"]["parameters"]
                salt_length = params["salt_length"].native if params is not None else hash_class.digest_size
                public_key.verify(
                    signature,
                    signed_bytes,
                    padding.PSS(mgf=padding.MGF1(hash_class()), salt_length=salt_length),
                    hash_class(),
                )
            else:
                public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_class())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_class()))
        else:
            _fail("ANCHOR_RECEIPT_MALFORMED", "a signer key type this implementation does not read")
    except InvalidSignature:
        _fail("ANCHOR_SIGNATURE_INVALID", "the token's CMS signature does not verify")


def verify_timestamp_authority(token: Any, roots: Any, imprint_input: Any, policy_oids: Optional[list] = None) -> dict:
    if not isinstance(roots, list) or len(roots) == 0:
        _fail("ANCHOR_UNTRUSTED_AUTHORITY", "authority verification requires at least one pinned root certificate")
    if not isinstance(imprint_input, (bytes, bytearray)) or len(imprint_input) == 0:
        _fail("ANCHOR_MALFORMED", "imprintInput must be the non-empty anchor-input byte string")

    der = _token_bytes(token)
    parsed = read_timestamp_token(der)
    signed_data = _parse_signed_data(der)
    signer_cert = _signer_certificate(signed_data)
    _require_timestamping_purpose(signer_cert)

    if policy_oids is not None:
        if not isinstance(policy_oids, list) or len(policy_oids) == 0:
            _fail("ANCHOR_MALFORMED", "policyOids, when given, must be a non-empty array")
        if parsed["policyOid"] not in policy_oids:
            _fail("ANCHOR_UNTRUSTED_AUTHORITY", f"the token was issued under policy {parsed['policyOid']}, which the caller does not admit")

    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$", parsed["genTime"])
    if match is None:
        _fail("ANCHOR_RECEIPT_MALFORMED", f'the token\'s genTime "{parsed["genTime"]}" is not a readable instant')
    fraction = (match.group(7) or "").ljust(6, "0")[:6]
    gen_time = datetime(
        int(match.group(1)), int(match.group(2)), int(match.group(3)),
        int(match.group(4)), int(match.group(5)), int(match.group(6)),
        int(fraction or 0), tzinfo=timezone.utc,
    )

    trusted = _load_pem_roots(roots)
    embedded = []
    for entry in signed_data["certificates"] or []:
        if entry.name == "certificate":
            embedded.append(x509.load_der_x509_certificate(entry.chosen.dump()))
    signer_loaded = x509.load_der_x509_certificate(signer_cert.dump())
    if not _chain_to_pinned_root(signer_loaded, embedded, trusted, gen_time):
        _fail("ANCHOR_UNTRUSTED_AUTHORITY", "the signing certificate does not chain to a pinned root at the token's genTime")

    _verify_cms_signature(signed_data, signer_cert)

    return {"genTime": parsed["genTime"], "policyOid": parsed["policyOid"]}
