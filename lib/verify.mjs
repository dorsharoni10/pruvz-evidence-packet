// The independent offline verifier (PRUVZ-88): one entry point that composes
// every verification layer this repository publishes — packet structure
// (lib/validator.mjs), canonical commitment (lib/canonical.mjs), seal and
// trust-registry rules (lib/trust-registry.mjs), the append-only log
// (lib/evidence-log.mjs) and external anchoring, both halves
// (lib/anchoring.mjs, lib/anchor-authority.mjs) — into one dimensional
// assurance report.
//
// The report is dimensional on purpose, and the overall verdict is a
// three-way summary, never a boolean:
//
//   FULLY_VERIFIED      — every dimension verified, nothing absent, nothing
//                         weakened. Unreachable when any required material is
//                         missing, whatever the reason for its absence.
//   PARTIALLY_VERIFIED  — nothing failed, but something could not be checked:
//                         absent material, a cost-gated capability the
//                         producing deployment did not run, a packet format
//                         that predates commitment-complete timelines.
//   NOT_VERIFIED        — something checked and failed. Presented material
//                         that fails verification is a refusal, never a
//                         downgrade to "partial".
//
// The verifier runs entirely offline: every input is a document the caller
// exported and saved, the trust anchor is a pinned { issuer, root } supplied
// out of band, and nothing here ever fetches anything. A verdict about a
// Pruvz record must never depend on asking Pruvz.
import { isDeepStrictEqual } from 'node:util'

import { validatePacket } from './validator.mjs'
import {
  CommitmentError,
  commitmentDigest,
  evidenceItemDocument,
  requireSupported as requireCommitmentSupported,
} from './canonical.mjs'
import {
  TrustRegistryError,
  acceptChain,
  keyStateAt,
  resolveSigningKey,
  verifySeal,
} from './trust-registry.mjs'
import {
  EvidenceLogError,
  acceptCheckpoint,
  sealLeafHash,
  validateCheckpointDocument,
  verifyCheckpoint,
  verifyInclusion,
} from './evidence-log.mjs'
import { AnchorError, anchorInput, verifyAnchorBinding } from './anchoring.mjs'
import { verifyTimestampAuthority } from './anchor-authority.mjs'

/** The verification-bundle format this implementation speaks. */
export const BUNDLE_FORMAT_VERSION = '1'

/** The three possible overall verdicts, strongest first. */
export const VERDICTS = ['FULLY_VERIFIED', 'PARTIALLY_VERIFIED', 'NOT_VERIFIED']

/**
 * Every reason code this layer itself can add to a report. Codes produced by
 * the composed layers (seal, registry, log, anchoring, commitment refusals)
 * flow through verbatim and are documented by their own layers; this list is
 * the verifier's own vocabulary, and it is closed.
 */
export const REASON_CODES = [
  'BUNDLE_MALFORMED',
  'PACKET_ABSENT',
  'PACKET_INVALID',
  'COMMITMENT_FIELDS_UNAVAILABLE',
  'TENANT_FROM_ENVELOPE',
  'TENANT_INCOHERENT',
  'TENANT_MISMATCH',
  'EVIDENCE_UNSEALED',
  'SEAL_WITHOUT_EVIDENCE',
  'SEAL_UNREADABLE',
  'SEAL_INVALID',
  'INCLUSION_PROOF_ABSENT',
  'INCLUSION_PROOF_INVALID',
  'LEAF_SEAL_MISMATCH',
  'CHECKPOINT_ABSENT',
  'CHECKPOINT_INVALID',
  'CHECKPOINT_KEY_UNTRUSTED',
  'CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY',
  'CHECKPOINT_CHAIN_REJECTED',
  'CONSISTENCY_NOT_PROVEN',
  'REGISTRY_ABSENT',
  'REGISTRY_REJECTED',
  'ANCHORS_ABSENT',
  'ANCHOR_NOT_WITNESSED',
  'ANCHOR_INVALID',
  'ANCHOR_AUTHORITY_NOT_EVALUATED',
  'REGISTRY_NOT_WITNESSED',
  'RETAINED_PROOF_ONLY',
  'PROFILE_MIXED',
  'COST_GATED_CAPABILITY_ABSENT',
  'STATE_FIRST_USE',
  'STATE_MALFORMED',
]

export class VerifierError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'VerifierError'
    this.code = code
  }
}

const fail = (code, message) => {
  throw new VerifierError(code, message)
}

const isPlainObject = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

const BUNDLE_MEMBERS = [
  'bundleFormatVersion',
  'packet',
  'seals',
  'proofs',
  'checkpoints',
  'consistencyProofs',
  'trustRegistry',
  'anchors',
]

/**
 * Structural admission of a bundle. Anything past this point may still fail
 * verification — that is the point of verification — but it fails as a
 * dimension result, not as a crash.
 */
const requireBundle = (bundle) => {
  if (!isPlainObject(bundle)) {
    fail('BUNDLE_MALFORMED', 'a verification bundle must be an object')
  }
  if (bundle.bundleFormatVersion !== BUNDLE_FORMAT_VERSION) {
    fail(
      'BUNDLE_MALFORMED',
      `this implementation speaks bundle format ${BUNDLE_FORMAT_VERSION}; got ` +
        `${bundle.bundleFormatVersion === undefined ? '(none)' : `"${bundle.bundleFormatVersion}"`}`,
    )
  }
  const unknown = Object.keys(bundle).filter((member) => !BUNDLE_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail('BUNDLE_MALFORMED', `a bundle carries ${unknown.join(', ')}; the member set is closed`)
  }
  const packet = bundle.packet ?? null
  if (packet !== null && !isPlainObject(packet)) {
    fail('BUNDLE_MALFORMED', 'bundle.packet must be the packet document, or null for proof-only bundles')
  }
  const seals = bundle.seals ?? {}
  if (!isPlainObject(seals)) {
    fail('BUNDLE_MALFORMED', 'bundle.seals must map evidenceId to the served seal response')
  }
  const proofs = bundle.proofs ?? {}
  if (!isPlainObject(proofs)) {
    fail('BUNDLE_MALFORMED', 'bundle.proofs must map evidenceId to the served inclusion-proof response')
  }
  const checkpoints = bundle.checkpoints ?? []
  if (!Array.isArray(checkpoints)) {
    fail('BUNDLE_MALFORMED', 'bundle.checkpoints must be an array of served signed checkpoints')
  }
  const consistencyProofs = bundle.consistencyProofs ?? []
  if (!Array.isArray(consistencyProofs)) {
    fail('BUNDLE_MALFORMED', 'bundle.consistencyProofs must be an array of served consistency proofs')
  }
  const trustRegistry = bundle.trustRegistry ?? null
  if (trustRegistry !== null && (!Array.isArray(trustRegistry) || trustRegistry.length === 0)) {
    fail(
      'BUNDLE_MALFORMED',
      'bundle.trustRegistry must be the served registry documents in version order, or absent',
    )
  }
  const anchors = bundle.anchors ?? {}
  if (!isPlainObject(anchors)) {
    fail('BUNDLE_MALFORMED', 'bundle.anchors must be an object of served anchors responses')
  }
  return { packet, seals, proofs, checkpoints, consistencyProofs, trustRegistry, anchors }
}

const STATE_MEMBERS = ['registry', 'checkpoint']
const ROOT_HASH = /^sha256:[0-9a-f]{64}$/u
const isSafePositive = (value) => Number.isSafeInteger(value) && value > 0

/**
 * Held state decides whether a later export is ordinary history, a rollback or
 * a fork, so a file that is not exactly what a previous run returned is
 * unusable input and is refused as such. It must never be reinterpreted into an
 * accusation against the evidence (a half-written checkpoint would fail the
 * log's document rules and surface as a rejected chain), and it must never be
 * quietly accepted in a shape that silently disables the protection it exists
 * to provide (an empty object compares against nothing).
 */
const requireState = (state) => {
  if (state === null) return
  if (!isPlainObject(state)) {
    fail('STATE_MALFORMED', 'state must be the object a previous verifyBundle returned')
  }
  const unknown = Object.keys(state).filter((member) => !STATE_MEMBERS.includes(member))
  if (unknown.length > 0) {
    fail('STATE_MALFORMED', `held state carries ${unknown.join(', ')}; the member set is closed`)
  }
  const checkpoint = state.checkpoint ?? null
  if (checkpoint === null) return
  if (
    !isPlainObject(checkpoint) ||
    !isSafePositive(checkpoint.checkpointSequence) ||
    !isSafePositive(checkpoint.treeSize) ||
    typeof checkpoint.origin !== 'string' ||
    checkpoint.origin.length === 0 ||
    typeof checkpoint.rootHash !== 'string' ||
    !ROOT_HASH.test(checkpoint.rootHash)
  ) {
    fail(
      'STATE_MALFORMED',
      'state.checkpoint must carry checkpointSequence, origin, rootHash and treeSize exactly ' +
        'as a previous run returned them, or be null',
    )
  }
}

const requirePin = (pin) => {
  if (!isPlainObject(pin) || typeof pin.issuer !== 'string' || typeof pin.root !== 'string') {
    fail(
      'BUNDLE_MALFORMED',
      'verifyBundle requires a pinned { issuer, root } supplied out of band; there is no pinless mode',
    )
  }
}

/** Anchors responses arrive verbatim ({ anchors, anchoringEnabled, ... }) or as bare arrays. */
const anchorRecordsOf = (entry) => {
  if (Array.isArray(entry)) return entry
  if (isPlainObject(entry) && Array.isArray(entry.anchors)) return entry.anchors
  fail('BUNDLE_MALFORMED', 'an anchors entry must be the served anchors response or an array of records')
}

const supportsCommitmentFields = (version) => {
  const [major, minor] = String(version).split('.').map(Number)
  return major > 1 || (major === 1 && minor >= 5)
}

/**
 * Verifies one exported verification bundle against a pinned trust anchor and
 * returns the dimensional assurance report. Throws a VerifierError only when
 * the bundle or the options are structurally unusable; every verification
 * outcome — including every failure — is a report, so that a caller always
 * learns WHICH dimension failed and why.
 *
 * Options:
 * - `pin` (required)      — { issuer, root }: the out-of-band trust anchor
 *   (docs/TRUST-REGISTRY.md section 4). Never taken from the bundle.
 * - `expectedTenantId`    — the tenant the caller believes this record belongs
 *   to. When absent it is taken from the seal envelopes themselves and the
 *   report says so: the envelopes are signed, so the binding still holds, but
 *   the verifier can then no longer catch a record presented under the wrong
 *   tenant label.
 * - `tsaRoots`            — PEM certificates pinned for anchor half two
 *   (docs/ANCHORING.md section 6). Absent: bindings are still checked, and the
 *   authority dimension honestly reports NOT_EVALUATED.
 * - `tsaPolicyOids`       — optional allowlist of admissible RFC 3161 policies.
 * - `state`               — the state a previous run returned ({ registry,
 *   checkpoint }), continuing this verifier's held history so rollback and
 *   fork presentations become refusals (docs/TRUST-REGISTRY.md section 8,
 *   docs/EVIDENCE-LOG.md section 7).
 */
export async function verifyBundle(bundle, { pin, expectedTenantId = null, tsaRoots = null, tsaPolicyOids = null, state = null } = {}) {
  const parts = requireBundle(bundle)
  requirePin(pin)
  requireState(state)

  const hard = new Set()
  const weak = new Set()
  const info = new Set()
  const explanations = []
  const explain = (code, message) => explanations.push({ code, message })

  // ── Trust registry ────────────────────────────────────────────────────────
  let registry = null
  let registryDimension
  if (parts.trustRegistry === null) {
    weak.add('REGISTRY_ABSENT')
    explain(
      'REGISTRY_ABSENT',
      'The bundle carries no trust-registry documents: no signature in it can be tied to a ' +
        'recognized signing identity, and every signature dimension below is NOT_CHECKED.',
    )
    registryDimension = { status: 'ABSENT' }
  } else {
    try {
      registry = acceptChain(parts.trustRegistry, { pin, state: state?.registry ?? null })
      for (const code of registry.reasonCodes) {
        weak.add(code)
      }
      registryDimension = {
        status: 'ACCEPTED',
        registryVersion: registry.manifest.registryVersion,
        rootStatus: registry.rootStatus,
        reasonCodes: [...registry.reasonCodes],
      }
      if ((state?.registry ?? null) === null) {
        info.add('STATE_FIRST_USE')
      }
    } catch (error) {
      if (!(error instanceof TrustRegistryError)) throw error
      hard.add('REGISTRY_REJECTED')
      hard.add(error.code)
      explain(error.code, error.message)
      registryDimension = { status: 'REJECTED', reasonCode: error.code }
    }
  }

  // ── Packet ────────────────────────────────────────────────────────────────
  let packetDimension
  let commitmentComputable = false
  if (parts.packet === null) {
    weak.add('PACKET_ABSENT')
    weak.add('RETAINED_PROOF_ONLY')
    explain(
      'RETAINED_PROOF_ONLY',
      'The bundle carries proof material without the packet payload (for example after ' +
        'retention deleted the record). What survives proves the sealed record existed and is ' +
        'covered by the log; it does not make the payload available, and is never presented as ' +
        'if it did.',
    )
    packetDimension = { status: 'ABSENT' }
  } else {
    const { valid, version, errors } = validatePacket(parts.packet)
    if (!valid) {
      hard.add('PACKET_INVALID')
      explain(
        'PACKET_INVALID',
        `The packet does not conform to format ${version}: ` +
          errors
            .slice(0, 3)
            .map((e) => `${e.instancePath} ${e.message}`)
            .join('; ') +
          (errors.length > 3 ? ` (and ${errors.length - 3} more)` : ''),
      )
      packetDimension = { status: 'INVALID', packetFormatVersion: version, errors }
    } else {
      packetDimension = { status: 'VALID', packetFormatVersion: version }
      commitmentComputable = supportsCommitmentFields(version)
      if (!commitmentComputable) {
        weak.add('COMMITMENT_FIELDS_UNAVAILABLE')
        explain(
          'COMMITMENT_FIELDS_UNAVAILABLE',
          `Packet format ${version} predates 1.5.0 and does not expose the four commitment-bound ` +
            'item fields (runId, schemaVersion, clientOperationId, payloadMetadata); the ' +
            'commitment digest a seal names cannot be recomputed from this packet.',
        )
      }
    }
  }

  // ── Tenant binding ────────────────────────────────────────────────────────
  const envelopeTenants = new Set(
    Object.values(parts.seals)
      .map((seal) => seal?.envelope?.subject?.tenantId)
      .filter((tenant) => typeof tenant === 'string'),
  )
  // One record has one tenant, and a tenant the caller pinned is a pin — in a
  // proof-only bundle exactly as much as in one carrying its packet. Taking the
  // subject from the seal's own claim is the fallback for a caller who named no
  // tenant, never a way for a supplied tenant to go unchecked.
  if (envelopeTenants.size > 1) {
    hard.add('TENANT_INCOHERENT')
    explain(
      'TENANT_INCOHERENT',
      `The seals in this bundle name ${envelopeTenants.size} different tenants; one record ` +
        'has one tenant, so the bundle is incoherent.',
    )
  }
  let tenantId = expectedTenantId
  if (tenantId === null) {
    if (envelopeTenants.size === 1) {
      tenantId = [...envelopeTenants][0]
      info.add('TENANT_FROM_ENVELOPE')
    }
  } else if (envelopeTenants.size > 0 && !envelopeTenants.has(tenantId)) {
    hard.add('TENANT_MISMATCH')
    explain(
      'TENANT_MISMATCH',
      `The caller pinned tenant "${tenantId}", but this bundle is sealed for ` +
        `${[...envelopeTenants].map((tenant) => `"${tenant}"`).join(', ')} — the material ` +
        'belongs to another tenant.',
    )
  }

  // ── Checkpoints: validity, key trust, acceptance chain ────────────────────
  // Every signed checkpoint in the bundle — served directly or embedded in an
  // inclusion proof — is collected, signature-verified under the registry, and
  // threaded through the acceptance rules in sequence order.
  const signedCheckpoints = new Map() // checkpointSequence -> { checkpoint, signature }
  const considerCheckpoint = (entry, where) => {
    if (!isPlainObject(entry) || !isPlainObject(entry.checkpoint)) {
      hard.add('CHECKPOINT_INVALID')
      explain('CHECKPOINT_INVALID', `${where} does not carry a { checkpoint, signature } document`)
      return
    }
    const sequence = entry.checkpoint.checkpointSequence
    const held = signedCheckpoints.get(sequence)
    // Compared as documents, not as byte strings: the same checkpoint served
    // twice — directly and embedded in an inclusion proof, or through a holder
    // who reformatted their saved export — is one checkpoint, whatever order its
    // keys were serialized in. Only a real disagreement is a fork, and calling
    // anything else one would accuse genuine evidence of forgery.
    if (held !== undefined && !isDeepStrictEqual(held, entry)) {
      hard.add('CHECKPOINT_CHAIN_REJECTED')
      hard.add('CHECKPOINT_FORK')
      explain(
        'CHECKPOINT_FORK',
        `The bundle carries two different checkpoints numbered ${sequence} — the log presented two histories.`,
      )
      return
    }
    signedCheckpoints.set(sequence, entry)
  }
  for (const [index, entry] of parts.checkpoints.entries()) {
    considerCheckpoint(entry, `bundle.checkpoints[${index}]`)
  }
  for (const [evidenceId, proof] of Object.entries(parts.proofs)) {
    if (isPlainObject(proof) && proof.checkpoint !== undefined) {
      considerCheckpoint(proof.checkpoint, `the inclusion proof of ${evidenceId}`)
    }
  }

  const checkpointTrust = new Map() // checkpointSequence -> true when signature + key trust held
  let latestProfile = null
  const profiles = new Set()
  for (const [sequence, entry] of [...signedCheckpoints.entries()].sort((a, b) => a[0] - b[0])) {
    let trusted = false
    try {
      if (registry !== null) {
        const { key, reason } = resolveSigningKey(registry.manifest, entry.checkpoint?.signer?.keyId)
        if (reason !== null) {
          hard.add('CHECKPOINT_KEY_UNTRUSTED')
          hard.add(reason)
          explain(reason, `Checkpoint ${sequence} is signed by a key the registry does not recognize as an evidence-signing key.`)
        } else {
          const stateWhenSigned = keyStateAt(key, entry.checkpoint.issuedAt)
          if (stateWhenSigned !== 'ACTIVE') {
            hard.add('CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY')
            explain(
              'CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY',
              `Checkpoint ${sequence} was signed while its key was ${stateWhenSigned}.`,
            )
          } else {
            verifyCheckpoint({ checkpoint: entry.checkpoint, signature: entry.signature, jwk: key.publicKey })
            trusted = true
            if (key.revokedAtUtc !== null) {
              weak.add('SIGNED_BEFORE_REVOCATION')
              weak.add('COMMITTED_AT_SELF_ASSERTED')
            }
          }
        }
      } else {
        // No registry: a signature can neither pass nor fail, because there is
        // no recognized key to check it under. The document itself is still
        // validated so garbage is refused loudly.
        validateCheckpointDocument(entry.checkpoint)
      }
    } catch (error) {
      if (!(error instanceof EvidenceLogError)) throw error
      if (registry !== null) {
        hard.add('CHECKPOINT_INVALID')
        hard.add(error.code)
        explain(error.code, `Checkpoint ${sequence}: ${error.message}`)
      }
      // Without a registry a signature can neither pass nor fail; only
      // structural refusals are meaningful, and those surface via acceptance.
    }
    checkpointTrust.set(sequence, trusted)
    if (typeof entry.checkpoint?.assuranceProfile === 'string') {
      profiles.add(entry.checkpoint.assuranceProfile)
      latestProfile = entry.checkpoint.assuranceProfile
    }
  }

  // Acceptance: thread held state through every trusted checkpoint in order,
  // connecting consecutive tree sizes with the bundle's consistency proofs.
  const consistencyBySizes = new Map()
  for (const proof of parts.consistencyProofs) {
    if (isPlainObject(proof)) {
      consistencyBySizes.set(`${proof.fromSize}->${proof.toSize}`, proof.proof ?? [])
    }
  }
  // Two distinct questions, answered separately. First: are the checkpoints
  // INSIDE this bundle one consistent history (threaded oldest-to-newest with
  // their consistency proofs — an internal fork or shrink is a refusal)?
  // Second: how does that history relate to the state this verifier already
  // HOLDS? A bundle may legitimately carry checkpoints older than the held
  // state — it is an export snapshot, not a claim of currency — so an older
  // export is reported as unconnected history, and the held state is NEVER
  // regressed. What held state refuses outright is a contradiction: a
  // checkpoint at a held sequence naming a different tree.
  const stateOf = (checkpoint) => ({
    checkpointSequence: checkpoint.checkpointSequence,
    origin: checkpoint.origin,
    rootHash: checkpoint.rootHash,
    treeSize: checkpoint.treeSize,
  })
  const held = state?.checkpoint ?? null
  let acceptedState = held
  let consistencyDimension = { status: 'NOT_APPLICABLE' }
  let checkpointDimension
  if (signedCheckpoints.size === 0) {
    weak.add('CHECKPOINT_ABSENT')
    checkpointDimension = { status: 'ABSENT' }
  } else {
    checkpointDimension = { status: 'ACCEPTED', sequences: [...signedCheckpoints.keys()].sort((a, b) => a - b) }
    if (held === null) {
      info.add('STATE_FIRST_USE')
    }
    const ordered = [...signedCheckpoints.entries()].sort((a, b) => a[0] - b[0]).map(([, entry]) => entry)
    if (ordered.length > 1 || held !== null) {
      consistencyDimension = { status: 'PROVEN' }
    }
    const connect = (accepted, entry, what) => {
      const candidate = entry.checkpoint
      const proof =
        accepted === null || accepted.treeSize === candidate.treeSize
          ? []
          : consistencyBySizes.get(`${accepted.treeSize}->${candidate.treeSize}`)
      if (accepted !== null && accepted.treeSize < candidate.treeSize && proof === undefined) {
        weak.add('CONSISTENCY_NOT_PROVEN')
        explain(
          'CONSISTENCY_NOT_PROVEN',
          `No consistency proof connects tree size ${accepted.treeSize} to ` +
            `${candidate.treeSize} (${what}); the later checkpoint stands alone rather than ` +
            'proving append-only extension.',
        )
        consistencyDimension = { status: 'NOT_PROVEN' }
        return stateOf(candidate)
      }
      return acceptCheckpoint({ accepted, candidate, consistencyProof: proof })
    }
    try {
      // Internal threading of the bundle's own history — every checkpoint,
      // verified or not, because an internally contradictory history is a
      // refusal whether or not its signatures could be checked at all.
      //
      // What may be REMEMBERED is narrower than what is CHECKED: only a
      // checkpoint whose signature verified under the pinned registry enters
      // the history this verifier carries forward. Otherwise one bundle served
      // without a trust registry — a published, PARTIALLY_VERIFIED shape —
      // could plant a head that makes every genuine export afterwards look like
      // stale history, permanently, since held state never regresses.
      let internal = null
      let retained = null
      let newestRetained = null
      for (const entry of ordered) {
        internal = connect(internal, entry, 'inside the bundle')
        if (checkpointTrust.get(entry.checkpoint?.checkpointSequence) === true) {
          retained = internal
          newestRetained = entry
        }
      }
      // Reconciliation with held state.
      if (newestRetained === null) {
        weak.add('CHECKPOINT_KEY_UNTRUSTED')
        explain(
          'CHECKPOINT_KEY_UNTRUSTED',
          'No checkpoint in this bundle could be verified under the pinned registry, so none of ' +
            'them enters the history this verifier carries forward: unverifiable material is ' +
            'reported, never remembered.',
        )
        acceptedState = held
      } else if (held === null) {
        acceptedState = retained
      } else {
        if (newestRetained.checkpoint.checkpointSequence >= held.checkpointSequence) {
          acceptedState = connect(held, newestRetained, 'from the held verifier state')
        } else {
          weak.add('CONSISTENCY_NOT_PROVEN')
          explain(
            'CONSISTENCY_NOT_PROVEN',
            `This bundle's newest verified checkpoint ` +
              `(${newestRetained.checkpoint.checkpointSequence}) is older ` +
              `than the held state (${held.checkpointSequence}): a historical export, verified ` +
              'as such. It cannot be connected forward, and it never regresses the held state.',
          )
          consistencyDimension = { status: 'NOT_PROVEN' }
          acceptedState = held
        }
      }
    } catch (error) {
      if (!(error instanceof EvidenceLogError)) throw error
      hard.add('CHECKPOINT_CHAIN_REJECTED')
      hard.add(error.code)
      explain(error.code, error.message)
      checkpointDimension = { status: 'REJECTED', reasonCode: error.code }
      consistencyDimension = { status: 'INVALID' }
      acceptedState = held
    }
  }

  // ── Evidence: commitment, seal, inclusion — one record at a time ──────────
  const packetItems = parts.packet?.evidence?.items ?? []
  const itemsById = new Map(packetItems.map((item) => [item.evidenceId, item]))
  const evidenceIds = parts.packet !== null ? packetItems.map((item) => item.evidenceId) : Object.keys(parts.seals)
  for (const evidenceId of Object.keys(parts.seals)) {
    if (parts.packet !== null && !itemsById.has(evidenceId)) {
      hard.add('SEAL_WITHOUT_EVIDENCE')
      explain(
        'SEAL_WITHOUT_EVIDENCE',
        `The bundle carries a seal for ${evidenceId}, which the packet's timeline does not contain.`,
      )
    }
  }

  const actionId = parts.packet?.action?.actionId ?? null
  const evidence = []
  for (const evidenceId of evidenceIds) {
    const item = itemsById.get(evidenceId) ?? null
    const seal = parts.seals[evidenceId] ?? null
    const entry = { evidenceId, sequence: item?.sequence ?? seal?.envelope?.subject?.sequence ?? null }

    // Commitment: recomputed from the record itself, never read off the seal.
    let expectedDigest = null
    if (item !== null && seal !== null && commitmentComputable) {
      try {
        requireCommitmentSupported(seal.envelope?.commitment?.version, seal.envelope?.commitment?.digestSuite)
        if (seal.envelope?.commitment?.kind !== 'evidence-item') {
          throw new CommitmentError(
            'UNSUPPORTED_KIND',
            `an evidence seal commits kind evidence-item; this envelope names "${seal.envelope?.commitment?.kind}"`,
          )
        }
        expectedDigest = commitmentDigest(
          'evidence-item',
          evidenceItemDocument({ tenantId: tenantId ?? seal.envelope?.subject?.tenantId, actionId, item }),
          seal.envelope.commitment.digestSuite,
        )
        entry.commitment = 'COMPUTED'
      } catch (error) {
        if (!(error instanceof CommitmentError)) throw error
        weak.add(error.code)
        explain(error.code, `Evidence ${evidenceId}: ${error.message}`)
        entry.commitment = 'NOT_COMPUTABLE'
      }
    } else {
      entry.commitment = 'NOT_COMPUTABLE'
    }

    // Seal: signature, key identity and lifecycle, subject, content.
    if (seal === null) {
      weak.add('EVIDENCE_UNSEALED')
      entry.seal = { status: 'ABSENT' }
      entry.commitment = 'NOT_CHECKED'
    } else if (registry === null) {
      entry.seal = { status: 'NOT_CHECKED' }
      if (expectedDigest !== null) {
        // Content binding is still checkable: does the record hash to what the
        // (unverified) envelope names? Origin stays NOT_CHECKED.
        entry.commitment = expectedDigest === seal.envelope?.commitment?.digest ? 'MATCHES_ENVELOPE' : 'MISMATCH'
        if (entry.commitment === 'MISMATCH') {
          hard.add('COMMITMENT_MISMATCH')
          explain(
            'COMMITMENT_MISMATCH',
            `Evidence ${evidenceId} does not hash to the digest its own envelope names — the record was altered.`,
          )
        }
      }
    } else {
      try {
        const expectedSubject = item !== null && tenantId !== null
          ? { tenantId, actionId, evidenceId, sequence: item.sequence }
          : seal.envelope?.subject
        const result = verifySeal({
          seal,
          manifest: registry.manifest,
          expectedSubject,
          expectedCommitmentDigest: expectedDigest,
          registryReasonCodes: registry.reasonCodes,
        })
        entry.seal = { status: result.verdict, dimensions: result.dimensions, reasonCodes: result.reasonCodes }
        if (result.verdict === 'INVALID') {
          hard.add('SEAL_INVALID')
          for (const code of result.reasonCodes) hard.add(code)
          explain(
            result.reasonCodes[result.reasonCodes.length - 1] ?? 'SEAL_INVALID',
            `Evidence ${evidenceId}: the seal does not verify.`,
          )
        } else if (result.verdict === 'PARTIAL') {
          for (const code of result.reasonCodes) weak.add(code)
        }
        entry.commitment =
          result.dimensions.content === 'MATCHES'
            ? 'MATCHES'
            : result.dimensions.content === 'MISMATCH'
              ? 'MISMATCH'
              : entry.commitment === 'COMPUTED'
                ? 'NOT_CHECKED'
                : entry.commitment
        if (typeof seal.envelope?.assuranceProfile === 'string') {
          profiles.add(seal.envelope.assuranceProfile)
        }
      } catch (error) {
        if (!(error instanceof TrustRegistryError)) throw error
        hard.add('SEAL_UNREADABLE')
        hard.add(error.code)
        explain(error.code, `Evidence ${evidenceId}: ${error.message}`)
        entry.seal = { status: 'INVALID', reasonCode: error.code }
      }
    }

    // Inclusion: the seal's leaf hash must sit at the proof's position of a
    // trusted checkpoint's tree.
    const proof = parts.proofs[evidenceId] ?? null
    if (proof === null) {
      if (seal !== null) {
        weak.add('INCLUSION_PROOF_ABSENT')
      }
      entry.inclusion = { status: 'ABSENT' }
    } else if (seal === null) {
      weak.add('INCLUSION_PROOF_ABSENT')
      entry.inclusion = { status: 'NOT_CHECKED' }
    } else {
      try {
        const leafHash = sealLeafHash(seal)
        if (proof.leafHash !== leafHash) {
          hard.add('LEAF_SEAL_MISMATCH')
          explain(
            'LEAF_SEAL_MISMATCH',
            `Evidence ${evidenceId}: the inclusion proof names a different leaf than this seal hashes to.`,
          )
          entry.inclusion = { status: 'INVALID', reasonCode: 'LEAF_SEAL_MISMATCH' }
        } else {
          const checkpoint = proof.checkpoint?.checkpoint
          verifyInclusion({
            leafHash: proof.leafHash,
            leafIndex: proof.leafIndex,
            treeSize: checkpoint?.treeSize,
            path: proof.path,
            rootHash: String(checkpoint?.rootHash ?? '').replace(/^sha256:/u, ''),
          })
          const trusted = checkpointTrust.get(checkpoint?.checkpointSequence) === true
          entry.inclusion = {
            status: trusted ? 'PROVEN' : 'PROVEN_AGAINST_UNVERIFIED_CHECKPOINT',
            checkpointSequence: checkpoint?.checkpointSequence ?? null,
          }
          if (!trusted) {
            weak.add('CHECKPOINT_KEY_UNTRUSTED')
          }
        }
      } catch (error) {
        if (!(error instanceof EvidenceLogError)) throw error
        hard.add('INCLUSION_PROOF_INVALID')
        hard.add(error.code)
        explain(error.code, `Evidence ${evidenceId}: ${error.message}`)
        entry.inclusion = { status: 'INVALID', reasonCode: error.code }
      }
    }
    evidence.push(entry)
  }

  // ── Anchors: were checkpoint and key history witnessed outside Pruvz? ─────
  const anchorsDimension = { checkpoints: {}, trustRegistry: {}, status: 'ABSENT' }
  let anyWitnessed = false
  let anyBindingOnly = false
  let anyAnchorInvalid = false
  let anyAnchorPending = false

  const checkAnchors = async (records, kind, subject, label, resultSlot) => {
    const results = []
    for (const raw of records) {
      const record = raw
      try {
        const binding = verifyAnchorBinding({ record, subject })
        if (tsaRoots === null) {
          anyBindingOnly = true
          results.push({ anchorId: record.anchorId, status: 'BINDING_ONLY', genTime: binding.genTime })
        } else {
          const authority = await verifyTimestampAuthority({
            token: record.receipt.token,
            roots: tsaRoots,
            imprintInput: anchorInput(kind, record.blindingNonce, subject),
            policyOids: tsaPolicyOids,
          })
          anyWitnessed = true
          results.push({
            anchorId: record.anchorId,
            status: 'WITNESSED',
            genTime: authority.genTime,
            policyOid: authority.policyOid,
            trustDomain: record.trustDomain,
          })
        }
      } catch (error) {
        if (!(error instanceof AnchorError)) throw error
        if (error.code === 'ANCHOR_NOT_PRESENT') {
          anyAnchorPending = true
          weak.add('ANCHOR_NOT_WITNESSED')
          results.push({ anchorId: record?.anchorId ?? null, status: record?.status ?? 'UNKNOWN' })
        } else {
          anyAnchorInvalid = true
          hard.add('ANCHOR_INVALID')
          hard.add(error.code)
          explain(error.code, `${label}: ${error.message}`)
          results.push({ anchorId: record?.anchorId ?? null, status: 'INVALID', reasonCode: error.code })
        }
      }
    }
    resultSlot(results)
  }

  const checkpointAnchors = isPlainObject(parts.anchors.checkpoints) ? parts.anchors.checkpoints : {}
  for (const [sequenceText, entry] of Object.entries(checkpointAnchors)) {
    const sequence = Number(sequenceText)
    const signedCheckpoint = signedCheckpoints.get(sequence)
    if (signedCheckpoint === undefined) {
      // A bundle-assembly gap, not failed evidence: these anchors cannot be
      // checked against anything, so they weaken the verdict rather than
      // refuting the record.
      weak.add('ANCHOR_NOT_WITNESSED')
      explain(
        'ANCHOR_NOT_WITNESSED',
        `The bundle carries anchors for checkpoint ${sequenceText} but not that signed checkpoint itself, so they cannot be checked.`,
      )
      continue
    }
    await checkAnchors(
      anchorRecordsOf(entry),
      'log-checkpoint',
      { checkpoint: signedCheckpoint.checkpoint, signature: signedCheckpoint.signature },
      `checkpoint ${sequenceText} anchor`,
      (results) => {
        anchorsDimension.checkpoints[sequenceText] = results
      },
    )
  }

  const registryAnchors = isPlainObject(parts.anchors.trustRegistry) ? parts.anchors.trustRegistry : {}
  for (const [versionText, entry] of Object.entries(registryAnchors)) {
    const document = (parts.trustRegistry ?? []).find(
      (candidate) => candidate?.manifest?.registryVersion === Number(versionText),
    )
    if (document === undefined) {
      weak.add('ANCHOR_NOT_WITNESSED')
      explain(
        'ANCHOR_NOT_WITNESSED',
        `The bundle carries anchors for trust-registry version ${versionText} but not that registry document, so they cannot be checked.`,
      )
      continue
    }
    await checkAnchors(
      anchorRecordsOf(entry),
      'trust-registry',
      { manifest: document.manifest, signatures: document.signatures },
      `trust-registry version ${versionText} anchor`,
      (results) => {
        anchorsDimension.trustRegistry[versionText] = results
      },
    )
  }

  const anyAnchorRecords =
    Object.keys(anchorsDimension.checkpoints).length > 0 || Object.keys(anchorsDimension.trustRegistry).length > 0
  if (!anyAnchorRecords) {
    weak.add('ANCHORS_ABSENT')
    if (latestProfile === 'PRE_CUSTOMER_DEFAULT') {
      weak.add('COST_GATED_CAPABILITY_ABSENT')
      explain(
        'COST_GATED_CAPABILITY_ABSENT',
        'External anchoring is cost-gated and this deployment profile does not run it. Its ' +
          'absence is reported honestly: nothing here was witnessed outside Pruvz, and the ' +
          'verdict can never be FULLY_VERIFIED without it.',
      )
    }
    anchorsDimension.status = 'ABSENT'
  } else if (anyAnchorInvalid) {
    anchorsDimension.status = 'INVALID'
  } else if (anyWitnessed && !anyBindingOnly && !anyAnchorPending) {
    anchorsDimension.status = 'WITNESSED'
  } else if (anyBindingOnly) {
    weak.add('ANCHOR_AUTHORITY_NOT_EVALUATED')
    explain(
      'ANCHOR_AUTHORITY_NOT_EVALUATED',
      'Anchor bindings were checked, but no timestamp-authority roots were pinned, so the ' +
        'receipts themselves were not authenticated (docs/ANCHORING.md section 6, half two).',
    )
    anchorsDimension.status = 'BINDING_ONLY'
  } else {
    anchorsDimension.status = 'PARTIAL'
  }
  if (anyAnchorRecords && Object.keys(anchorsDimension.trustRegistry).length === 0) {
    weak.add('REGISTRY_NOT_WITNESSED')
  }

  // ── Assurance profile ─────────────────────────────────────────────────────
  // A bundle whose only profile statement is in its seal envelopes still
  // declares one; the cost-gated reading above must not go silent merely
  // because no checkpoint came with it.
  if (latestProfile === null && profiles.size === 1) {
    latestProfile = [...profiles][0]
  }
  let profileDimension
  if (profiles.size === 0) {
    profileDimension = { status: 'UNKNOWN', declared: [] }
  } else if (profiles.size === 1) {
    profileDimension = { status: 'CONSISTENT', declared: [...profiles] }
  } else {
    weak.add('PROFILE_MIXED')
    explain(
      'PROFILE_MIXED',
      `The material in this bundle was produced under ${profiles.size} different assurance profiles.`,
    )
    profileDimension = { status: 'MIXED', declared: [...profiles].sort() }
  }

  // ── Roll-up ───────────────────────────────────────────────────────────────
  const sealStatuses = evidence.map((entry) => entry.seal?.status)
  const sealsDimension = {
    status: sealStatuses.some((status) => status === 'INVALID')
      ? 'INVALID'
      : sealStatuses.some((status) => status === 'ABSENT' || status === 'NOT_CHECKED')
        ? 'INCOMPLETE'
        : sealStatuses.some((status) => status === 'PARTIAL')
          ? 'PARTIAL'
          : sealStatuses.length > 0
            ? 'VALID'
            : 'ABSENT',
  }
  const commitmentStates = evidence.map((entry) => entry.commitment)
  const commitmentDimension = {
    status: commitmentStates.some((status) => status === 'MISMATCH')
      ? 'MISMATCH'
      : commitmentStates.length > 0 && commitmentStates.every((status) => status === 'MATCHES')
        ? 'MATCHES'
        : commitmentStates.some((status) => status === 'MATCHES' || status === 'MATCHES_ENVELOPE')
          ? 'PARTIAL'
          : 'NOT_CHECKED',
  }
  const inclusionStates = evidence.map((entry) => entry.inclusion?.status)
  const inclusionDimension = {
    status: inclusionStates.some((status) => status === 'INVALID')
      ? 'INVALID'
      : inclusionStates.length > 0 && inclusionStates.every((status) => status === 'PROVEN')
        ? 'PROVEN'
        : inclusionStates.some((status) => status === 'PROVEN' || status === 'PROVEN_AGAINST_UNVERIFIED_CHECKPOINT')
          ? 'PARTIAL'
          : 'ABSENT',
  }

  const UNSUPPORTED_CODES = [
    'UNKNOWN_SUITE',
    'UNKNOWN_ENVELOPE_VERSION',
    'UNKNOWN_COMMITMENT_VERSION',
    'UNKNOWN_DIGEST_SUITE',
    'UNKNOWN_KEY_USE',
    'UNSUPPORTED_KIND',
    'ANCHOR_SUITE_UNSUPPORTED',
  ]
  const suiteSupportStatus = UNSUPPORTED_CODES.some((code) => hard.has(code) || weak.has(code))
    ? 'UNSUPPORTED'
    : 'SUPPORTED'

  const verdict = hard.size > 0 ? 'NOT_VERIFIED' : weak.size > 0 ? 'PARTIALLY_VERIFIED' : 'FULLY_VERIFIED'

  return {
    verifierFormatVersion: '1',
    verdict,
    reasonCodes: [...new Set([...hard, ...weak, ...info])].sort(),
    explanations,
    dimensions: {
      packet: packetDimension,
      commitment: commitmentDimension,
      seals: sealsDimension,
      trustRegistry: registryDimension,
      logInclusion: inclusionDimension,
      logConsistency: consistencyDimension,
      checkpoints: checkpointDimension,
      anchors: anchorsDimension,
      assuranceProfile: profileDimension,
      suiteSupport: { status: suiteSupportStatus },
      retention: { status: parts.packet === null ? 'PROOF_ONLY' : 'PAYLOAD_PRESENT' },
    },
    evidence,
    state: {
      registry: registry?.state ?? state?.registry ?? null,
      checkpoint: acceptedState,
    },
  }
}
