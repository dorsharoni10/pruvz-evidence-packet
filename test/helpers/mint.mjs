// Test-only minting of a complete, coherent verification bundle: a trust
// registry, evidence seals over a published 1.5.0 example packet, an
// append-only log with signed checkpoints, and a synthetic RFC 3161 authority
// whose chain the tests pin. Everything is built through the SAME published
// building blocks the verifier checks against (lib/canonical.mjs,
// lib/trust-registry.mjs, lib/evidence-log.mjs, lib/anchoring.mjs), so a
// minted bundle is valid because the rules say so — not because the test and
// the verifier share a shortcut.
//
// Signing here uses an ephemeral in-memory key per run. That is a fixture
// property, not a product claim: the product's non-exportable managed-key
// posture is out of scope for a test helper.
import { generateKeyPairSync, randomBytes, sign as signEcdsa, webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'

import { commitmentDigest, evidenceItemDocument } from '../../lib/canonical.mjs'
import { jwkThumbprint, manifestInput, rootPinFromManifest, sealSigningInput } from '../../lib/trust-registry.mjs'
import {
  checkpointSigningInput,
  consistencyProof,
  inclusionPath,
  sealLeafHash,
  treeHead,
} from '../../lib/evidence-log.mjs'
import { anchorImprint } from '../../lib/anchoring.mjs'

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

export const ORIGIN = 'pruvz.ai/evidence-log/mint'
export const ISSUER = 'pruvz.ai'
export const TENANT = 'tenant-demo'
export const PROFILE = 'PRE_CUSTOMER_DEFAULT'
export const TSA_POLICY_OID = '1.3.6.1.4.1.99999.1'

const base64url = (bytes) => Buffer.from(bytes).toString('base64url')

const makeKeyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  return { privateKey, publicKey: { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } }
}

const signP1363 = (privateKey, input) =>
  base64url(signEcdsa('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }))

/** A published 1.5.0 example packet, as the fixture's payload. */
export const loadExamplePacket = (name = 'verified-refund.packet.json') =>
  JSON.parse(readFileSync(path.join(repoRoot, 'examples', 'valid', name), 'utf8'))

const registryKey = ({ keyId, publicKey, use }) => ({
  keyId,
  predecessorKeyId: null,
  provider: 'local-development',
  publicKey,
  retiredAtUtc: null,
  revocationReason: null,
  revokedAtUtc: null,
  status: 'ACTIVE',
  suite: 'ES256',
  thumbprint: jwkThumbprint(publicKey),
  use,
  validFromUtc: '2026-07-01T00:00:00Z',
})

/**
 * A registry chain of one version: an active trust root and an active evidence
 * key. Returns { documents, pin, root, evidence } where root/evidence carry the
 * private keys the other minting steps sign with.
 */
export const makeRegistry = () => {
  const root = { ...makeKeyPair(), keyId: 'mint:keys/trust-root/1' }
  const evidence = { ...makeKeyPair(), keyId: 'mint:keys/evidence-signing/1' }
  const manifest = {
    formatVersion: '1',
    issuedAtUtc: '2026-08-01T00:00:00Z',
    issuer: ISSUER,
    keys: [
      registryKey({ keyId: root.keyId, publicKey: root.publicKey, use: 'trust-root' }),
      registryKey({ keyId: evidence.keyId, publicKey: evidence.publicKey, use: 'evidence-signing' }),
    ],
    previous: null,
    registryVersion: 1,
  }
  const document = {
    manifest,
    signatures: [
      { keyId: root.keyId, signature: signP1363(root.privateKey, manifestInput(manifest)), suite: 'ES256' },
    ],
    attestations: { publications: [], witnesses: [] },
  }
  return { documents: [document], pin: rootPinFromManifest(document), root, evidence }
}

/** Seals every item of a packet with the evidence key, in sequence order. */
export const makeSeals = (packet, evidence) => {
  const seals = {}
  for (const item of packet.evidence.items) {
    const envelope = {
      assuranceProfile: PROFILE,
      commitment: {
        digest: commitmentDigest(
          'evidence-item',
          evidenceItemDocument({ tenantId: TENANT, actionId: packet.action.actionId, item }),
        ),
        digestSuite: 'sha-256',
        kind: 'evidence-item',
        version: '1',
      },
      committedAt: item.recordedAtUtc,
      signer: { keyId: evidence.keyId, provider: 'local-development', suite: 'ES256' },
      subject: {
        actionId: packet.action.actionId,
        evidenceId: item.evidenceId,
        sequence: item.sequence,
        tenantId: TENANT,
      },
      version: '1',
    }
    seals[item.evidenceId] = { envelope, signature: signP1363(evidence.privateKey, sealSigningInput(envelope)) }
  }
  return seals
}

const makeCheckpoint = (evidence, sequence, issuedAt, leafHashes) => {
  const checkpoint = {
    assuranceProfile: PROFILE,
    checkpointSequence: sequence,
    issuedAt,
    origin: ORIGIN,
    rootHash: `sha256:${treeHead(leafHashes)}`,
    signer: { keyId: evidence.keyId, provider: 'local-development', suite: 'ES256' },
    treeSize: leafHashes.length,
    version: '1',
  }
  return { checkpoint, signature: signP1363(evidence.privateKey, checkpointSigningInput(checkpoint)) }
}

/**
 * The append-only log of a packet's seals: every leaf, one mid-history
 * checkpoint, one covering checkpoint, the consistency proof connecting them,
 * and an inclusion proof for every record against the covering checkpoint.
 */
export const makeLog = (packet, seals, evidence) => {
  const items = packet.evidence.items
  const leafHashes = items.map((item) => sealLeafHash(seals[item.evidenceId]))
  const midSize = Math.max(1, leafHashes.length - 2)
  const first = makeCheckpoint(evidence, 1, '2026-08-10T09:00:00Z', leafHashes.slice(0, midSize))
  const last = makeCheckpoint(evidence, 2, '2026-08-10T09:01:00Z', leafHashes)
  const proofs = {}
  for (const [index, item] of items.entries()) {
    proofs[item.evidenceId] = {
      leafIndex: index,
      leafHash: leafHashes[index],
      path: inclusionPath(index, leafHashes),
      checkpoint: last,
    }
  }
  return {
    leafHashes,
    checkpoints: [first, last],
    proofs,
    consistencyProofs: [
      { fromSize: midSize, toSize: leafHashes.length, proof: consistencyProof(midSize, leafHashes) },
    ],
  }
}

// ── Synthetic RFC 3161 authority ────────────────────────────────────────────
// A two-certificate chain (self-signed root CA, timestamping leaf) minted per
// run. The leaf's extended key usage is critical and names exactly
// id-kp-timeStamping, because that is what half two requires of a real
// authority; the tests pin the minted root.

const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2'

/**
 * pkijs emits CMS eContent as a BER constructed OCTET STRING; the published
 * strict DER reader (and DER itself) requires the primitive form. The CMS
 * signature covers the content VALUE, not its framing, so collapsing every
 * constructed OCTET STRING into its primitive equivalent is a pure re-framing.
 */
const withPrimitiveOctetStrings = (ber) => {
  const parsed = asn1js.fromBER(ber)
  if (parsed.offset === -1) {
    throw new Error('minted token does not re-parse')
  }
  const collapse = (node) => {
    const block = node?.idBlock
    if (block === undefined) {
      return node
    }
    if (block.tagClass === 1 && block.tagNumber === 4 && block.isConstructed) {
      const chunks = node.valueBlock.value.map((chunk) => Buffer.from(chunk.valueBlock.valueHexView))
      const joined = Buffer.concat(chunks)
      return new asn1js.OctetString({
        valueHex: joined.buffer.slice(joined.byteOffset, joined.byteOffset + joined.byteLength),
      })
    }
    if (Array.isArray(node.valueBlock?.value)) {
      node.valueBlock.value = node.valueBlock.value.map(collapse)
    }
    return node
  }
  return Buffer.from(collapse(parsed.result).toBER(false))
}

const distinguishedName = (commonName) => [
  new pkijs.AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value: commonName }) }),
]

const makeCertificate = async ({ subject, issuer, serial, publicKey, extensions }) => {
  const certificate = new pkijs.Certificate()
  certificate.version = 2
  certificate.serialNumber = new asn1js.Integer({ value: serial })
  certificate.issuer.typesAndValues.push(...distinguishedName(issuer))
  certificate.subject.typesAndValues.push(...distinguishedName(subject))
  certificate.notBefore.value = new Date('2020-01-01T00:00:00Z')
  certificate.notAfter.value = new Date('2040-01-01T00:00:00Z')
  certificate.extensions = extensions
  await certificate.subjectPublicKeyInfo.importKey(publicKey)
  return certificate
}

/**
 * Options exist only to mint DEFECTIVE authorities for negative tests:
 * `ekuCritical: false` drops the criticality half two requires, and
 * `extraPurpose: true` adds a second key purpose so timestamping is no longer
 * the sole one. The default mints a conformant authority.
 *
 * `crossSignedRoot: true` mints a CONFORMANT authority shaped like a public
 * one: beside the chain that ends at the self-signed root, the token also
 * embeds a second certificate with the root's exact name and key, issued by
 * an older root nobody pins (DigiCert's responder embeds "DigiCert Trusted
 * Root G4" issued by "DigiCert Assured ID Root CA" this way). A verifier that
 * lets the look-alike displace the pinned anchor refuses a genuine token.
 */
export const makeAuthority = async ({
  ekuCritical = true,
  extraPurpose = false,
  crossSignedRoot = false,
} = {}) => {
  const rootKeys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])
  const leafKeys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])
  const legacyRootKeys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])

  const rootCertificate = await makeCertificate({
    subject: 'Pruvz Mint TSA Root',
    issuer: 'Pruvz Mint TSA Root',
    serial: 1,
    publicKey: rootKeys.publicKey,
    extensions: [
      new pkijs.Extension({
        extnID: '2.5.29.19', // basicConstraints
        critical: true,
        extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false),
      }),
    ],
  })
  await rootCertificate.sign(rootKeys.privateKey, 'SHA-256')

  const leafCertificate = await makeCertificate({
    subject: 'Pruvz Mint TSA',
    issuer: 'Pruvz Mint TSA Root',
    serial: 2,
    publicKey: leafKeys.publicKey,
    extensions: [
      new pkijs.Extension({
        extnID: '2.5.29.37', // extendedKeyUsage: critical, timestamping only (unless minting a defect)
        critical: ekuCritical,
        extnValue: new pkijs.ExtKeyUsage({
          keyPurposes: extraPurpose
            ? ['1.3.6.1.5.5.7.3.8', '1.3.6.1.5.5.7.3.1']
            : ['1.3.6.1.5.5.7.3.8'],
        })
          .toSchema()
          .toBER(false),
      }),
    ],
  })
  await leafCertificate.sign(rootKeys.privateKey, 'SHA-256')

  // The cross-signed look-alike: same subject and same public key as the
  // root, but issued (and signed) by a legacy root that is never pinned.
  // Listed FIRST among the embedded certificates, where DigiCert puts it.
  const embedded = [rootCertificate, leafCertificate]
  if (crossSignedRoot) {
    const crossSigned = await makeCertificate({
      subject: 'Pruvz Mint TSA Root',
      issuer: 'Pruvz Mint Legacy Root',
      serial: 3,
      publicKey: rootKeys.publicKey,
      extensions: [
        new pkijs.Extension({
          extnID: '2.5.29.19', // basicConstraints
          critical: true,
          extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(false),
        }),
      ],
    })
    await crossSigned.sign(legacyRootKeys.privateKey, 'SHA-256')
    embedded.unshift(crossSigned)
  }

  const rootPem =
    '-----BEGIN CERTIFICATE-----\n' +
    Buffer.from(rootCertificate.toSchema().toBER(false)).toString('base64') +
    '\n-----END CERTIFICATE-----\n'

  /** Mints one token over an imprint, answering one request nonce. */
  const mintToken = async ({ imprint, requestNonce, genTime = '2026-08-30T12:00:00Z' }) => {
    const tstInfo = new pkijs.TSTInfo({
      version: 1,
      policy: TSA_POLICY_OID,
      messageImprint: new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1' }),
        hashedMessage: new asn1js.OctetString({ valueHex: imprint }),
      }),
      serialNumber: new asn1js.Integer({ value: Date.now() % 1000000 }),
      genTime: new Date(genTime),
      nonce: new asn1js.Integer({
        valueHex: requestNonce.buffer.slice(requestNonce.byteOffset, requestNonce.byteOffset + requestNonce.byteLength),
      }),
    })
    const tstDer = tstInfo.toSchema().toBER(false)
    const signedData = new pkijs.SignedData({
      version: 3,
      encapContentInfo: new pkijs.EncapsulatedContentInfo({
        eContentType: OID_TST_INFO,
        eContent: new asn1js.OctetString({ valueHex: tstDer }),
      }),
      signerInfos: [
        new pkijs.SignerInfo({
          version: 1,
          sid: new pkijs.IssuerAndSerialNumber({
            issuer: leafCertificate.issuer,
            serialNumber: leafCertificate.serialNumber,
          }),
        }),
      ],
      certificates: embedded,
    })
    await signedData.sign(leafKeys.privateKey, 0, 'SHA-256', tstDer)
    const contentInfo = new pkijs.ContentInfo({
      contentType: OID_SIGNED_DATA,
      content: signedData.toSchema(true),
    })
    return withPrimitiveOctetStrings(contentInfo.toSchema().toBER(false)).toString('base64')
  }

  return { rootPem, mintToken }
}

/** One ANCHORED record witnessing a subject through the minted authority. */
export const makeAnchor = async ({ authority, kind, subject, subjectVersion, anchorId, genTime }) => {
  const blindingNonce = randomBytes(32)
  // First byte below 0x80 keeps the DER INTEGER encoding free of a sign octet.
  const requestNonce = Buffer.concat([Buffer.from([0x01]), randomBytes(15)])
  const imprint = anchorImprint(kind, blindingNonce, subject)
  const token = await authority.mintToken({
    imprint: imprint.buffer.slice(imprint.byteOffset, imprint.byteOffset + imprint.byteLength),
    requestNonce,
    genTime,
  })
  return {
    version: '1',
    anchorId,
    trustDomain: 'mint-tsa',
    status: 'ANCHORED',
    subject: {
      kind,
      origin: kind === 'log-checkpoint' ? subject.checkpoint.origin : subject.manifest.issuer,
      subjectVersion,
    },
    blindingNonce: base64url(blindingNonce),
    requestNonce: base64url(requestNonce),
    receipt: { kind: 'rfc3161-timestamp-token', token },
  }
}

/**
 * A complete coherent bundle over one example packet: registry, seals, log,
 * inclusion and consistency proofs, and — when `withAnchors` — a witnessed
 * anchor for the covering checkpoint and for the registry version.
 */
export const mintBundle = async ({ withAnchors = true, packetName, authorityOptions = {} } = {}) => {
  const packet = loadExamplePacket(packetName)
  const registry = makeRegistry()
  const seals = makeSeals(packet, registry.evidence)
  const log = makeLog(packet, seals, registry.evidence)

  const bundle = {
    bundleFormatVersion: '1',
    packet,
    seals,
    proofs: log.proofs,
    checkpoints: log.checkpoints,
    consistencyProofs: log.consistencyProofs,
    trustRegistry: registry.documents,
    anchors: {},
  }

  let authority = null
  if (withAnchors) {
    authority = await makeAuthority(authorityOptions)
    const covering = log.checkpoints[log.checkpoints.length - 1]
    const checkpointAnchor = await makeAnchor({
      authority,
      kind: 'log-checkpoint',
      subject: { checkpoint: covering.checkpoint, signature: covering.signature },
      subjectVersion: covering.checkpoint.checkpointSequence,
      anchorId: 'anc_mint_checkpoint_2',
      genTime: '2026-08-30T12:00:00Z',
    })
    const registryDocument = registry.documents[0]
    const registryAnchor = await makeAnchor({
      authority,
      kind: 'trust-registry',
      subject: { manifest: registryDocument.manifest, signatures: registryDocument.signatures },
      subjectVersion: registryDocument.manifest.registryVersion,
      anchorId: 'anc_mint_registry_1',
      genTime: '2026-08-30T12:00:01Z',
    })
    bundle.anchors = {
      checkpoints: {
        [String(covering.checkpoint.checkpointSequence)]: {
          anchors: [checkpointAnchor],
          anchoringEnabled: true,
          trustDomain: 'mint-tsa',
          note: 'minted by the test fixture',
        },
      },
      trustRegistry: {
        1: { anchors: [registryAnchor], anchoringEnabled: true, trustDomain: 'mint-tsa', note: 'minted by the test fixture' },
      },
    }
  }

  return { bundle, pin: registry.pin, registry, seals, log, authority, tsaRoots: authority ? [authority.rootPem] : null }
}
