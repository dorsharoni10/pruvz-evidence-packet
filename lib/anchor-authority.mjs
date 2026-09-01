// Half two of anchor verification (docs/ANCHORING.md section 6): is the
// RFC 3161 timestamp token itself authentic? Half one — verifyAnchorBinding in
// lib/anchoring.mjs — establishes that a token witnesses THIS subject under
// THIS record's nonces, and deliberately checks nothing about the authority.
// This module answers the other half: the CMS signature over the token, the
// signer's sole and critical timestamping purpose, the signer's validity at
// the token's own genTime (a historical anchor must not expire), and a chain
// that ends at a root the CALLER pinned — never an ambient trust store.
//
// The split is published in the anchoring golden vectors as
// `runtimeDivergence`: a token whose signature bytes were altered still binds
// (its messageImprint is untouched), so a half-one implementation accepts it
// and this module must refuse it.
//
// Composition only: every primitive (SHA-2, ECDSA/RSA, ASN.1/CMS parsing and
// signature verification, certificate chain building) comes from maintained
// libraries — node:crypto and pkijs. Nothing cryptographic is invented here.
import { webcrypto, X509Certificate } from 'node:crypto'
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

import { AnchorError, readTimestampToken } from './anchoring.mjs'

pkijs.setEngine('pruvz-verifier', new pkijs.CryptoEngine({ name: 'pruvz-verifier', crypto: webcrypto }))

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'
const OID_EXTENDED_KEY_USAGE = '2.5.29.37'
const OID_EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'

const fail = (code, message) => {
  throw new AnchorError(code, message)
}

/** Strict base64 (the DER token as stored in a record's receipt). */
const tokenBytes = (token) => {
  if (typeof token !== 'string' || token.length === 0) {
    fail('ANCHOR_MALFORMED', 'receipt.token must be a non-empty base64 string')
  }
  const decoded = Buffer.from(token, 'base64')
  if (
    decoded.length === 0 ||
    decoded.toString('base64').replace(/=+$/u, '') !== token.replace(/=+$/u, '')
  ) {
    fail('ANCHOR_MALFORMED', 'receipt.token is not valid base64')
  }
  return decoded
}

const pemToCertificate = (pem, index) => {
  const match = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\r\n]+)-----END CERTIFICATE-----/u.exec(pem)
  if (!match) {
    fail('ANCHOR_MALFORMED', `pinned root ${index} is not a PEM certificate`)
  }
  const der = Buffer.from(match[1].replace(/[\r\n]/gu, ''), 'base64')
  return pkijs.Certificate.fromBER(der)
}

/**
 * Every certificate embedded in a token, as PEM. A caller deciding what to pin
 * — a test pinning a vector authority, an operator making a deliberate pin
 * decision — reads the candidates from here; nothing in this module ever
 * treats an embedded certificate as trusted by virtue of being embedded.
 */
export function embeddedCertificates(token) {
  const signedData = parseSignedData(tokenBytes(token))
  return (signedData.certificates ?? [])
    .filter((entry) => entry instanceof pkijs.Certificate)
    .map((certificate) => {
      const der = Buffer.from(certificate.toSchema().toBER(false))
      return new X509Certificate(der).toString()
    })
}

const parseSignedData = (der) => {
  let contentInfo
  try {
    contentInfo = pkijs.ContentInfo.fromBER(der)
  } catch {
    fail('ANCHOR_RECEIPT_MALFORMED', 'receipt.token is not a DER ContentInfo')
  }
  if (contentInfo.contentType !== OID_SIGNED_DATA) {
    fail('ANCHOR_RECEIPT_MALFORMED', `receipt.token is ${contentInfo.contentType}, not CMS SignedData`)
  }
  let signedData
  try {
    signedData = new pkijs.SignedData({ schema: contentInfo.content })
  } catch {
    fail('ANCHOR_RECEIPT_MALFORMED', 'receipt.token does not carry parseable SignedData')
  }
  if (signedData.encapContentInfo.eContentType !== OID_TST_INFO) {
    fail(
      'ANCHOR_RECEIPT_MALFORMED',
      `the signed content is ${signedData.encapContentInfo.eContentType}, not a TSTInfo`,
    )
  }
  return signedData
}

const signerCertificate = (signedData) => {
  if (!Array.isArray(signedData.signerInfos) || signedData.signerInfos.length !== 1) {
    fail('ANCHOR_RECEIPT_MALFORMED', 'a timestamp token carries exactly one SignerInfo')
  }
  const sid = signedData.signerInfos[0].sid
  const certificates = signedData.certificates ?? []
  const found = certificates.find(
    (certificate) =>
      certificate instanceof pkijs.Certificate &&
      sid instanceof pkijs.IssuerAndSerialNumber &&
      certificate.issuer.isEqual(sid.issuer) &&
      certificate.serialNumber.isEqual(sid.serialNumber),
  )
  if (!found) {
    fail('ANCHOR_RECEIPT_MALFORMED', 'the signing certificate is not embedded in the token')
  }
  return found
}

/**
 * The timestamping purpose must be the certificate's sole purpose and the
 * extension must be critical (RFC 3161 section 2.3). A certificate that may
 * also do other things is not a timestamping identity.
 */
const requireTimestampingPurpose = (certificate) => {
  const extension = (certificate.extensions ?? []).find((ext) => ext.extnID === OID_EXTENDED_KEY_USAGE)
  if (!extension) {
    fail('ANCHOR_UNTRUSTED_AUTHORITY', 'the signing certificate declares no extended key usage')
  }
  if (extension.critical !== true) {
    fail(
      'ANCHOR_UNTRUSTED_AUTHORITY',
      'the extended key usage of a timestamping certificate must be critical',
    )
  }
  let purposes
  try {
    purposes = new pkijs.ExtKeyUsage({
      schema: asn1js.fromBER(extension.extnValue.valueBlock.valueHexView).result,
    }).keyPurposes
  } catch {
    fail('ANCHOR_RECEIPT_MALFORMED', 'the extended key usage extension is not parseable')
  }
  if (purposes.length !== 1 || purposes[0] !== OID_EKU_TIME_STAMPING) {
    fail(
      'ANCHOR_UNTRUSTED_AUTHORITY',
      `the signing certificate's purposes are [${purposes.join(', ')}]; ` +
        'a timestamping certificate carries exactly id-kp-timeStamping',
    )
  }
}

/**
 * Verifies the authority half of one RFC 3161 timestamp token against pinned
 * roots. Returns { genTime, policyOid, signerSubject } on success; throws an
 * AnchorError naming the first failed rule otherwise.
 *
 * - `roots` — one or more PEM certificates the caller pinned out of band.
 *   There is no ambient-trust-store mode: an empty pin set is a refusal,
 *   because "some root my platform happens to ship" is not a decision.
 * - The chain and every certificate in it are evaluated at the token's OWN
 *   genTime, so a historical anchor stays verifiable after the authority's
 *   certificates expire. What genTime cannot do is prove itself — it is the
 *   authority's assertion, trusted exactly as far as the pinned authority is.
 * - `imprintInput` — the exact byte string the anchor imprint was taken over
 *   (lib/anchoring.mjs `anchorInput`). The CMS layer re-derives the message
 *   imprint from it, so the token's TSTInfo is verified against the subject's
 *   real bytes here as well — the same fact half one establishes, proved once
 *   more inside the authenticated envelope.
 * - `policyOids` — optional allowlist; when given, the token's policy must be
 *   in it.
 */
export async function verifyTimestampAuthority({ token, roots, imprintInput, policyOids = null } = {}) {
  if (!Array.isArray(roots) || roots.length === 0) {
    fail(
      'ANCHOR_UNTRUSTED_AUTHORITY',
      'authority verification requires at least one pinned root certificate',
    )
  }
  if (!Buffer.isBuffer(imprintInput) || imprintInput.length === 0) {
    fail('ANCHOR_MALFORMED', 'imprintInput must be the non-empty anchor-input byte string')
  }

  const der = tokenBytes(token)
  const parsed = readTimestampToken(der) // shared TSTInfo reader: genTime, policyOid, imprint, nonce
  const signedData = parseSignedData(der)
  const certificate = signerCertificate(signedData)
  requireTimestampingPurpose(certificate)

  if (policyOids !== null) {
    if (!Array.isArray(policyOids) || policyOids.length === 0) {
      fail('ANCHOR_MALFORMED', 'policyOids, when given, must be a non-empty array')
    }
    if (!policyOids.includes(parsed.policyOid)) {
      fail(
        'ANCHOR_UNTRUSTED_AUTHORITY',
        `the token was issued under policy ${parsed.policyOid}, which the caller does not admit`,
      )
    }
  }

  const genTime = new Date(parsed.genTime)
  if (Number.isNaN(genTime.getTime())) {
    fail('ANCHOR_RECEIPT_MALFORMED', `the token's genTime "${parsed.genTime}" is not a readable instant`)
  }

  const trustedCerts = roots.map(pemToCertificate)

  // The chain is built from the token's embedded certificates and must end at
  // a pinned root; every certificate is checked for validity at genTime.
  //
  // An embedded certificate that carries a pinned root's NAME is left out of
  // the candidates. Public authorities routinely embed a cross-signed copy of
  // their own root (DigiCert's timestamp responder ships "DigiCert Trusted
  // Root G4" issued by "DigiCert Assured ID Root CA" beside the chain that
  // ends at the self-signed G4). pkijs builds paths by issuer name, so that
  // copy displaces the trust anchor the caller pinned and the path runs on
  // towards an issuer nobody pinned: "no valid certificate paths found" for a
  // token that is genuine. The pinned root is the anchor by definition — an
  // embedded certificate can only ever be an intermediate — so dropping the
  // look-alike is exactly what the Python and .NET verifiers already do by
  // terminating at a pinned root before consulting embedded candidates. It
  // never admits anything: the path must still end in `trustedCerts`, and a
  // look-alike carrying a different key was never going to be trusted.
  const namedAsPinnedRoot = (certificate) =>
    trustedCerts.some((root) => root.subject.isEqual(certificate.subject))
  const chainEngine = new pkijs.CertificateChainValidationEngine({
    certs: (signedData.certificates ?? []).filter(
      (entry) => entry instanceof pkijs.Certificate && !namedAsPinnedRoot(entry),
    ),
    trustedCerts,
    checkDate: genTime,
  })
  const chain = await chainEngine.verify()
  if (chain.result !== true) {
    fail(
      'ANCHOR_UNTRUSTED_AUTHORITY',
      "the signing certificate does not chain to a pinned root at the token's genTime" +
        (chain.resultMessage ? ` (${chain.resultMessage})` : ''),
    )
  }

  // The CMS signature itself: signed attributes (including message-digest over
  // the TSTInfo) and the signature value, under the signer certificate that
  // just proved its chain and purpose.
  let signatureVerifies
  try {
    signatureVerifies = await signedData.verify({
      signer: 0,
      data: imprintInput.buffer.slice(imprintInput.byteOffset, imprintInput.byteOffset + imprintInput.byteLength),
      trustedCerts,
      checkDate: genTime,
    })
  } catch (error) {
    fail(
      'ANCHOR_SIGNATURE_INVALID',
      `the token's CMS signature does not verify: ${error?.message ?? 'verification failed'}`,
    )
  }
  if (signatureVerifies !== true) {
    fail('ANCHOR_SIGNATURE_INVALID', "the token's CMS signature does not verify")
  }

  return {
    genTime: parsed.genTime,
    policyOid: parsed.policyOid,
    signerSubject: certificate.subject.typesAndValues
      .map((entry) => entry.value.valueBlock.value)
      .join(', '),
  }
}
