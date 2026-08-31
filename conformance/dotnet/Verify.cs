// The independent offline verifier — .NET implementation (PRUVZ-97), from
// docs/VERIFIER.md: one entry point composes every layer over an exported
// bundle into the dimensional assurance report. Missing material weakens and
// never passes; presented material that fails is a refusal, never a
// downgrade; a cost-gated capability the deployment did not run is reported
// honestly as absent and can never yield a full verdict.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace PruvzConformance;

public sealed class VerifierException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class Verify
{
    public const string BundleFormatVersion = "1";

    private static readonly string[] BundleMembers =
    [
        "bundleFormatVersion", "packet", "seals", "proofs", "checkpoints", "consistencyProofs", "trustRegistry", "anchors",
    ];
    private static readonly string[] StateMembers = ["registry", "checkpoint"];
    private static readonly Regex RootHashPattern = new("^sha256:[0-9a-f]{64}$", RegexOptions.Compiled);

    private static VerifierException Refuse(string code, string message) => new(code, message);

    private static JsonNode? NullableInteger(long? value) => value is null ? null : JsonValue.Create(value.Value);

    private sealed record BundleParts(
        JsonObject? Packet, JsonObject Seals, JsonObject Proofs, JsonArray Checkpoints,
        JsonArray ConsistencyProofs, JsonArray? TrustRegistry, JsonObject Anchors);

    private static BundleParts RequireBundle(JsonNode? node)
    {
        if (node is not JsonObject bundle)
        {
            throw Refuse("BUNDLE_MALFORMED", "a verification bundle must be an object");
        }
        if (Canonical.StringOf(bundle, "bundleFormatVersion") != BundleFormatVersion)
        {
            throw Refuse("BUNDLE_MALFORMED", $"this implementation speaks bundle format {BundleFormatVersion}");
        }
        var unknown = bundle.Select(pair => pair.Key).Where(member => !BundleMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("BUNDLE_MALFORMED", $"a bundle carries {string.Join(", ", unknown)}; the member set is closed");
        }
        var packetNode = bundle["packet"];
        if (packetNode is not null && packetNode is not JsonObject)
        {
            throw Refuse("BUNDLE_MALFORMED", "bundle.packet must be the packet document, or null");
        }
        var seals = bundle["seals"] switch { null => new JsonObject(), JsonObject o => o, _ => throw Refuse("BUNDLE_MALFORMED", "bundle.seals must be an object") };
        var proofs = bundle["proofs"] switch { null => new JsonObject(), JsonObject o => o, _ => throw Refuse("BUNDLE_MALFORMED", "bundle.proofs must be an object") };
        var checkpoints = bundle["checkpoints"] switch { null => new JsonArray(), JsonArray a => a, _ => throw Refuse("BUNDLE_MALFORMED", "bundle.checkpoints must be an array") };
        var consistency = bundle["consistencyProofs"] switch { null => new JsonArray(), JsonArray a => a, _ => throw Refuse("BUNDLE_MALFORMED", "bundle.consistencyProofs must be an array") };
        JsonArray? trustRegistry = bundle["trustRegistry"] switch
        {
            null => null,
            JsonArray a when a.Count > 0 => a,
            _ => throw Refuse("BUNDLE_MALFORMED", "bundle.trustRegistry must be the served registry documents in version order, or absent"),
        };
        var anchors = bundle["anchors"] switch { null => new JsonObject(), JsonObject o => o, _ => throw Refuse("BUNDLE_MALFORMED", "bundle.anchors must be an object") };
        return new BundleParts(packetNode as JsonObject, seals, proofs, checkpoints, consistency, trustRegistry, anchors);
    }

    private static void RequireState(JsonObject? state)
    {
        if (state is null)
        {
            return;
        }
        var unknown = state.Select(pair => pair.Key).Where(member => !StateMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("STATE_MALFORMED", $"held state carries {string.Join(", ", unknown)}; the member set is closed");
        }
        if (state["checkpoint"] is null)
        {
            return;
        }
        if (state["checkpoint"] is not JsonObject checkpoint
            || Registry.IntegerOf(checkpoint["checkpointSequence"]) is not > 0
            || Registry.IntegerOf(checkpoint["treeSize"]) is not > 0
            || string.IsNullOrEmpty(Canonical.StringOf(checkpoint, "origin"))
            || Canonical.StringOf(checkpoint, "rootHash") is not { } rootHash
            || !RootHashPattern.IsMatch(rootHash))
        {
            throw Refuse("STATE_MALFORMED", "state.checkpoint must carry checkpointSequence, origin, rootHash and treeSize");
        }
    }

    private static JsonArray AnchorRecordsOf(JsonNode? entry)
    {
        if (entry is JsonArray array)
        {
            return array;
        }
        if (entry is JsonObject obj && obj["anchors"] is JsonArray anchors)
        {
            return anchors;
        }
        throw Refuse("BUNDLE_MALFORMED", "an anchors entry must be the served anchors response or an array of records");
    }

    private static bool SupportsCommitmentFields(string version)
    {
        var parts = version.Split('.');
        return int.Parse(parts[0]) > 1 || (int.Parse(parts[0]) == 1 && int.Parse(parts[1]) >= 5);
    }

    public static JsonObject VerifyBundle(
        JsonNode? bundleNode, JsonObject pin, string? expectedTenantId,
        IReadOnlyList<string>? tsaRoots, IReadOnlyList<string>? tsaPolicyOids, JsonObject? state)
    {
        var parts = RequireBundle(bundleNode);
        if (Registry.AsString(pin["issuer"]) is null || Registry.AsString(pin["root"]) is null)
        {
            throw Refuse("BUNDLE_MALFORMED", "verifyBundle requires a pinned { issuer, root }; there is no pinless mode");
        }
        RequireState(state);

        var hard = new SortedSet<string>(StringComparer.Ordinal);
        var weak = new SortedSet<string>(StringComparer.Ordinal);
        var info = new SortedSet<string>(StringComparer.Ordinal);
        var explanations = new JsonArray();
        void Explain(string code, string message) =>
            explanations.Add(new JsonObject { ["code"] = code, ["message"] = message });

        // -- Trust registry --------------------------------------------------
        Registry.ChainOutcome? registry = null;
        JsonObject registryDimension;
        if (parts.TrustRegistry is null)
        {
            weak.Add("REGISTRY_ABSENT");
            Explain("REGISTRY_ABSENT", "The bundle carries no trust-registry documents.");
            registryDimension = new JsonObject { ["status"] = "ABSENT" };
        }
        else
        {
            try
            {
                registry = Registry.AcceptChain(parts.TrustRegistry, pin, state?["registry"] as JsonObject);
                foreach (var code in registry.ReasonCodes)
                {
                    weak.Add(code);
                }
                registryDimension = new JsonObject
                {
                    ["status"] = "ACCEPTED",
                    ["registryVersion"] = registry.Accepted.Manifest.RegistryVersion,
                    ["rootStatus"] = registry.Accepted.RootStatus,
                    ["reasonCodes"] = new JsonArray(registry.ReasonCodes.Select(code => (JsonNode)code).ToArray()),
                };
                if (state?["registry"] is null)
                {
                    info.Add("STATE_FIRST_USE");
                }
            }
            catch (TrustRegistryException error)
            {
                hard.Add("REGISTRY_REJECTED");
                hard.Add(error.Code);
                Explain(error.Code, error.Message);
                registryDimension = new JsonObject { ["status"] = "REJECTED", ["reasonCode"] = error.Code };
            }
        }

        // -- Packet ----------------------------------------------------------
        JsonObject packetDimension;
        var commitmentComputable = false;
        if (parts.Packet is null)
        {
            weak.Add("PACKET_ABSENT");
            weak.Add("RETAINED_PROOF_ONLY");
            Explain("RETAINED_PROOF_ONLY", "The bundle carries proof material without the packet payload.");
            packetDimension = new JsonObject { ["status"] = "ABSENT" };
        }
        else
        {
            var outcome = Validator.ValidatePacket(parts.Packet);
            if (!outcome.Valid)
            {
                hard.Add("PACKET_INVALID");
                Explain("PACKET_INVALID", $"The packet does not conform to format {outcome.Version}.");
                packetDimension = new JsonObject { ["status"] = "INVALID", ["packetFormatVersion"] = outcome.Version };
            }
            else
            {
                packetDimension = new JsonObject { ["status"] = "VALID", ["packetFormatVersion"] = outcome.Version };
                commitmentComputable = SupportsCommitmentFields(outcome.Version);
                if (!commitmentComputable)
                {
                    weak.Add("COMMITMENT_FIELDS_UNAVAILABLE");
                    Explain("COMMITMENT_FIELDS_UNAVAILABLE", $"Packet format {outcome.Version} predates 1.5.0.");
                }
            }
        }

        // -- Tenant binding --------------------------------------------------
        var envelopeTenants = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in parts.Seals)
        {
            if (pair.Value is JsonObject seal && seal["envelope"] is JsonObject envelope
                && envelope["subject"] is JsonObject subject && Canonical.StringOf(subject, "tenantId") is { } tenant)
            {
                envelopeTenants.Add(tenant);
            }
        }
        if (envelopeTenants.Count > 1)
        {
            hard.Add("TENANT_INCOHERENT");
            Explain("TENANT_INCOHERENT", "The seals in this bundle name different tenants.");
        }
        var tenantId = expectedTenantId;
        if (tenantId is null)
        {
            if (envelopeTenants.Count == 1)
            {
                tenantId = envelopeTenants.First();
                info.Add("TENANT_FROM_ENVELOPE");
            }
        }
        else if (envelopeTenants.Count > 0 && !envelopeTenants.Contains(tenantId))
        {
            hard.Add("TENANT_MISMATCH");
            Explain("TENANT_MISMATCH", $"The caller pinned tenant \"{tenantId}\", but this bundle is sealed for another.");
        }

        // -- Checkpoints -----------------------------------------------------
        var signedCheckpoints = new SortedDictionary<long, JsonObject>();
        void ConsiderCheckpoint(JsonNode? entryNode, string where)
        {
            if (entryNode is not JsonObject entry || entry["checkpoint"] is not JsonObject checkpoint)
            {
                hard.Add("CHECKPOINT_INVALID");
                Explain("CHECKPOINT_INVALID", $"{where} does not carry a checkpoint document");
                return;
            }
            var sequence = Registry.IntegerOf(checkpoint["checkpointSequence"]) ?? -1;
            if (signedCheckpoints.TryGetValue(sequence, out var held) && !JsonNode.DeepEquals(held, entry))
            {
                hard.Add("CHECKPOINT_CHAIN_REJECTED");
                hard.Add("CHECKPOINT_FORK");
                Explain("CHECKPOINT_FORK", $"The bundle carries two different checkpoints numbered {sequence}.");
                return;
            }
            signedCheckpoints[sequence] = entry;
        }
        for (var index = 0; index < parts.Checkpoints.Count; index += 1)
        {
            ConsiderCheckpoint(parts.Checkpoints[index], $"bundle.checkpoints[{index}]");
        }
        foreach (var pair in parts.Proofs)
        {
            if (pair.Value is JsonObject proof && proof["checkpoint"] is not null)
            {
                ConsiderCheckpoint(proof["checkpoint"], $"the inclusion proof of {pair.Key}");
            }
        }

        var checkpointTrust = new Dictionary<long, bool>();
        string? latestProfile = null;
        var profiles = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (sequence, entry) in signedCheckpoints)
        {
            var trusted = false;
            var checkpoint = (JsonObject)entry["checkpoint"]!;
            try
            {
                if (registry is not null)
                {
                    var signerKeyId = checkpoint["signer"] is JsonObject signer ? Canonical.StringOf(signer, "keyId") : null;
                    var (key, reason) = Registry.ResolveSigningKey(registry.Accepted.Manifest, signerKeyId);
                    if (reason is not null)
                    {
                        hard.Add("CHECKPOINT_KEY_UNTRUSTED");
                        hard.Add(reason);
                        Explain(reason, $"Checkpoint {sequence} is signed by a key the registry does not recognize.");
                    }
                    else
                    {
                        var stateWhenSigned = Registry.KeyStateAt(key!, Canonical.StringOf(checkpoint, "issuedAt")!);
                        if (stateWhenSigned != "ACTIVE")
                        {
                            hard.Add("CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY");
                            Explain("CHECKPOINT_SIGNED_OUTSIDE_KEY_VALIDITY", $"Checkpoint {sequence} was signed while its key was {stateWhenSigned}.");
                        }
                        else
                        {
                            EvidenceLog.VerifyCheckpoint(checkpoint, entry["signature"], key!.PublicKey);
                            trusted = true;
                            if (key.RevokedAtUtc is not null)
                            {
                                weak.Add("SIGNED_BEFORE_REVOCATION");
                                weak.Add("COMMITTED_AT_SELF_ASSERTED");
                            }
                        }
                    }
                }
                else
                {
                    EvidenceLog.ValidateCheckpointDocument(checkpoint);
                }
            }
            catch (EvidenceLogException error)
            {
                if (registry is not null)
                {
                    hard.Add("CHECKPOINT_INVALID");
                    hard.Add(error.Code);
                    Explain(error.Code, $"Checkpoint {sequence}: {error.Message}");
                }
            }
            checkpointTrust[sequence] = trusted;
            if (Canonical.StringOf(checkpoint, "assuranceProfile") is { } profile)
            {
                profiles.Add(profile);
                latestProfile = profile;
            }
        }

        var consistencyBySizes = new Dictionary<string, JsonArray>();
        foreach (var proofNode in parts.ConsistencyProofs)
        {
            if (proofNode is JsonObject proof)
            {
                consistencyBySizes[$"{Registry.IntegerOf(proof["fromSize"])}->{Registry.IntegerOf(proof["toSize"])}"] =
                    proof["proof"] as JsonArray ?? [];
            }
        }

        static JsonObject StateOf(JsonObject checkpoint) => new()
        {
            ["checkpointSequence"] = Registry.IntegerOf(checkpoint["checkpointSequence"])!.Value,
            ["origin"] = Canonical.StringOf(checkpoint, "origin"),
            ["rootHash"] = Canonical.StringOf(checkpoint, "rootHash"),
            ["treeSize"] = Registry.IntegerOf(checkpoint["treeSize"])!.Value,
        };

        var held = state?["checkpoint"] as JsonObject;
        var acceptedState = held;
        var consistencyDimension = new JsonObject { ["status"] = "NOT_APPLICABLE" };
        JsonObject checkpointDimension;
        if (signedCheckpoints.Count == 0)
        {
            weak.Add("CHECKPOINT_ABSENT");
            checkpointDimension = new JsonObject { ["status"] = "ABSENT" };
        }
        else
        {
            checkpointDimension = new JsonObject
            {
                ["status"] = "ACCEPTED",
                ["sequences"] = new JsonArray(signedCheckpoints.Keys.Select(key => (JsonNode)key).ToArray()),
            };
            if (held is null)
            {
                info.Add("STATE_FIRST_USE");
            }
            var ordered = signedCheckpoints.Values.ToList();
            if (ordered.Count > 1 || held is not null)
            {
                consistencyDimension = new JsonObject { ["status"] = "PROVEN" };
            }

            JsonObject? Connect(JsonObject? accepted, JsonObject entry, string what)
            {
                var candidate = (JsonObject)entry["checkpoint"]!;
                JsonArray? proof;
                if (accepted is null || Registry.IntegerOf(accepted["treeSize"]) == Registry.IntegerOf(candidate["treeSize"]))
                {
                    proof = [];
                }
                else
                {
                    consistencyBySizes.TryGetValue(
                        $"{Registry.IntegerOf(accepted["treeSize"])}->{Registry.IntegerOf(candidate["treeSize"])}", out proof);
                }
                if (accepted is not null
                    && Registry.IntegerOf(accepted["treeSize"]) < Registry.IntegerOf(candidate["treeSize"])
                    && proof is null)
                {
                    weak.Add("CONSISTENCY_NOT_PROVEN");
                    Explain(
                        "CONSISTENCY_NOT_PROVEN",
                        $"No consistency proof connects tree size {Registry.IntegerOf(accepted["treeSize"])} to {Registry.IntegerOf(candidate["treeSize"])} ({what}).");
                    consistencyDimension["status"] = "NOT_PROVEN";
                    return StateOf(candidate);
                }
                return EvidenceLog.AcceptCheckpoint(accepted, candidate, proof);
            }

            try
            {
                JsonObject? internalState = null;
                JsonObject? retained = null;
                JsonObject? newestRetained = null;
                foreach (var entry in ordered)
                {
                    internalState = Connect(internalState, entry, "inside the bundle");
                    var sequence = Registry.IntegerOf(((JsonObject)entry["checkpoint"]!)["checkpointSequence"]) ?? -1;
                    if (checkpointTrust.TryGetValue(sequence, out var isTrusted) && isTrusted)
                    {
                        retained = internalState;
                        newestRetained = entry;
                    }
                }
                if (newestRetained is null)
                {
                    weak.Add("CHECKPOINT_KEY_UNTRUSTED");
                    Explain("CHECKPOINT_KEY_UNTRUSTED", "No checkpoint in this bundle could be verified under the pinned registry.");
                    acceptedState = held;
                }
                else if (held is null)
                {
                    acceptedState = retained;
                }
                else
                {
                    var newestSequence = Registry.IntegerOf(((JsonObject)newestRetained["checkpoint"]!)["checkpointSequence"]);
                    if (newestSequence >= Registry.IntegerOf(held["checkpointSequence"]))
                    {
                        acceptedState = Connect(held, newestRetained, "from the held verifier state");
                    }
                    else
                    {
                        weak.Add("CONSISTENCY_NOT_PROVEN");
                        Explain("CONSISTENCY_NOT_PROVEN", "This bundle's newest verified checkpoint is older than the held state: a historical export.");
                        consistencyDimension["status"] = "NOT_PROVEN";
                        acceptedState = held;
                    }
                }
            }
            catch (EvidenceLogException error)
            {
                hard.Add("CHECKPOINT_CHAIN_REJECTED");
                hard.Add(error.Code);
                Explain(error.Code, error.Message);
                checkpointDimension = new JsonObject { ["status"] = "REJECTED", ["reasonCode"] = error.Code };
                consistencyDimension = new JsonObject { ["status"] = "INVALID" };
                acceptedState = held;
            }
        }

        // -- Evidence --------------------------------------------------------
        var packetItems = parts.Packet?["evidence"] is JsonObject evidenceObj && evidenceObj["items"] is JsonArray itemsArray
            ? itemsArray.Cast<JsonObject>().ToList()
            : [];
        var itemsById = packetItems.ToDictionary(item => Canonical.StringOf(item!, "evidenceId")!, item => item!);
        var evidenceIds = parts.Packet is not null
            ? packetItems.Select(item => Canonical.StringOf(item!, "evidenceId")!).ToList()
            : parts.Seals.Select(pair => pair.Key).ToList();
        foreach (var pair in parts.Seals)
        {
            if (parts.Packet is not null && !itemsById.ContainsKey(pair.Key))
            {
                hard.Add("SEAL_WITHOUT_EVIDENCE");
                Explain("SEAL_WITHOUT_EVIDENCE", $"The bundle carries a seal for {pair.Key}, which the packet's timeline does not contain.");
            }
        }

        var actionId = parts.Packet?["action"] is JsonObject action ? Canonical.StringOf(action, "actionId") : null;
        var evidenceResults = new JsonArray();
        foreach (var evidenceId in evidenceIds)
        {
            itemsById.TryGetValue(evidenceId, out var item);
            var seal = parts.Seals[evidenceId] as JsonObject;
            var entry = new JsonObject
            {
                ["evidenceId"] = evidenceId,
                ["sequence"] = NullableInteger(item is not null
                    ? Registry.IntegerOf(item["sequence"])
                    : seal?["envelope"] is JsonObject sealEnvelope && sealEnvelope["subject"] is JsonObject sealSubject
                        ? Registry.IntegerOf(sealSubject["sequence"])
                        : null),
            };

            string? expectedDigest = null;
            if (item is not null && seal is not null && commitmentComputable)
            {
                try
                {
                    var envelope = seal["envelope"] as JsonObject ?? [];
                    var commitment = envelope["commitment"] as JsonObject ?? [];
                    Canonical.RequireSupported(Canonical.StringOf(commitment, "version"), Canonical.StringOf(commitment, "digestSuite"));
                    if (Canonical.StringOf(commitment, "kind") != "evidence-item")
                    {
                        throw new CommitmentException("UNSUPPORTED_KIND", "an evidence seal commits kind evidence-item");
                    }
                    var subjectTenant = tenantId ?? (envelope["subject"] is JsonObject envelopeSubject ? Canonical.StringOf(envelopeSubject, "tenantId") : null);
                    expectedDigest = Canonical.CommitmentDigest(
                        "evidence-item",
                        Canonical.EvidenceItemDocument(new JsonObject
                        {
                            ["tenantId"] = subjectTenant,
                            ["actionId"] = actionId,
                            ["item"] = item.DeepClone(),
                        }),
                        Canonical.StringOf(commitment, "digestSuite") ?? "sha-256");
                    entry["commitment"] = "COMPUTED";
                }
                catch (CommitmentException error)
                {
                    weak.Add(error.Code);
                    Explain(error.Code, $"Evidence {evidenceId}: {error.Message}");
                    entry["commitment"] = "NOT_COMPUTABLE";
                }
            }
            else
            {
                entry["commitment"] = "NOT_COMPUTABLE";
            }

            if (seal is null)
            {
                weak.Add("EVIDENCE_UNSEALED");
                entry["seal"] = new JsonObject { ["status"] = "ABSENT" };
                entry["commitment"] = "NOT_CHECKED";
            }
            else if (registry is null)
            {
                entry["seal"] = new JsonObject { ["status"] = "NOT_CHECKED" };
                if (expectedDigest is not null)
                {
                    var envelopeDigest = seal["envelope"] is JsonObject digestEnvelope && digestEnvelope["commitment"] is JsonObject sealCommitment
                        ? Canonical.StringOf(sealCommitment, "digest")
                        : null;
                    entry["commitment"] = expectedDigest == envelopeDigest ? "MATCHES_ENVELOPE" : "MISMATCH";
                    if (Canonical.StringOf(entry, "commitment") == "MISMATCH")
                    {
                        hard.Add("COMMITMENT_MISMATCH");
                        Explain("COMMITMENT_MISMATCH", $"Evidence {evidenceId} does not hash to the digest its own envelope names.");
                    }
                }
            }
            else
            {
                try
                {
                    JsonObject? expectedSubject;
                    if (item is not null && tenantId is not null)
                    {
                        expectedSubject = new JsonObject
                        {
                            ["tenantId"] = tenantId,
                            ["actionId"] = actionId,
                            ["evidenceId"] = evidenceId,
                            ["sequence"] = JsonValue.Create(Registry.IntegerOf(item["sequence"])!.Value),
                        };
                    }
                    else
                    {
                        expectedSubject = seal["envelope"] is JsonObject subjectEnvelope ? subjectEnvelope["subject"] as JsonObject : null;
                    }
                    if (expectedSubject is null)
                    {
                        throw new TrustRegistryException("INVALID_MANIFEST", "expectedSubject is required");
                    }
                    var result = Registry.VerifySeal(seal, registry.Accepted.Manifest, expectedSubject, expectedDigest, registry.ReasonCodes);
                    entry["seal"] = new JsonObject
                    {
                        ["status"] = result.Verdict,
                        ["dimensions"] = new JsonObject(result.Dimensions.Select(pair => KeyValuePair.Create<string, JsonNode?>(pair.Key, pair.Value))),
                        ["reasonCodes"] = new JsonArray(result.ReasonCodes.Select(code => (JsonNode)code).ToArray()),
                    };
                    if (result.Verdict == "INVALID")
                    {
                        hard.Add("SEAL_INVALID");
                        foreach (var code in result.ReasonCodes)
                        {
                            hard.Add(code);
                        }
                        Explain(result.ReasonCodes.Count > 0 ? result.ReasonCodes[^1] : "SEAL_INVALID", $"Evidence {evidenceId}: the seal does not verify.");
                    }
                    else if (result.Verdict == "PARTIAL")
                    {
                        foreach (var code in result.ReasonCodes)
                        {
                            weak.Add(code);
                        }
                    }
                    entry["commitment"] = result.Dimensions["content"] switch
                    {
                        "MATCHES" => "MATCHES",
                        "MISMATCH" => "MISMATCH",
                        _ => Canonical.StringOf(entry, "commitment") == "COMPUTED" ? "NOT_CHECKED" : Canonical.StringOf(entry, "commitment"),
                    };
                    if (seal["envelope"] is JsonObject profileEnvelope && Canonical.StringOf(profileEnvelope, "assuranceProfile") is { } sealProfile)
                    {
                        profiles.Add(sealProfile);
                    }
                }
                catch (TrustRegistryException error)
                {
                    hard.Add("SEAL_UNREADABLE");
                    hard.Add(error.Code);
                    Explain(error.Code, $"Evidence {evidenceId}: {error.Message}");
                    entry["seal"] = new JsonObject { ["status"] = "INVALID", ["reasonCode"] = error.Code };
                }
            }

            var proof = parts.Proofs[evidenceId] as JsonObject;
            if (proof is null)
            {
                if (seal is not null)
                {
                    weak.Add("INCLUSION_PROOF_ABSENT");
                }
                entry["inclusion"] = new JsonObject { ["status"] = "ABSENT" };
            }
            else if (seal is null)
            {
                weak.Add("INCLUSION_PROOF_ABSENT");
                entry["inclusion"] = new JsonObject { ["status"] = "NOT_CHECKED" };
            }
            else
            {
                try
                {
                    var leafHash = EvidenceLog.SealLeafHash(seal);
                    if (Canonical.StringOf(proof, "leafHash") != leafHash)
                    {
                        hard.Add("LEAF_SEAL_MISMATCH");
                        Explain("LEAF_SEAL_MISMATCH", $"Evidence {evidenceId}: the inclusion proof names a different leaf than this seal hashes to.");
                        entry["inclusion"] = new JsonObject { ["status"] = "INVALID", ["reasonCode"] = "LEAF_SEAL_MISMATCH" };
                    }
                    else
                    {
                        var checkpoint = proof["checkpoint"] is JsonObject proofCheckpoint ? proofCheckpoint["checkpoint"] as JsonObject : null;
                        EvidenceLog.VerifyInclusion(
                            Canonical.StringOf(proof, "leafHash"),
                            Registry.IntegerOf(proof["leafIndex"]),
                            checkpoint is null ? null : Registry.IntegerOf(checkpoint["treeSize"]),
                            proof["path"] as JsonArray,
                            (checkpoint is null ? "" : Canonical.StringOf(checkpoint, "rootHash") ?? "").Replace("sha256:", ""));
                        var sequence = checkpoint is null ? -1 : Registry.IntegerOf(checkpoint["checkpointSequence"]) ?? -1;
                        var trusted = checkpointTrust.TryGetValue(sequence, out var isTrusted) && isTrusted;
                        entry["inclusion"] = new JsonObject
                        {
                            ["status"] = trusted ? "PROVEN" : "PROVEN_AGAINST_UNVERIFIED_CHECKPOINT",
                            ["checkpointSequence"] = NullableInteger(checkpoint is null ? null : Registry.IntegerOf(checkpoint["checkpointSequence"])),
                        };
                        if (!trusted)
                        {
                            weak.Add("CHECKPOINT_KEY_UNTRUSTED");
                        }
                    }
                }
                catch (EvidenceLogException error)
                {
                    hard.Add("INCLUSION_PROOF_INVALID");
                    hard.Add(error.Code);
                    Explain(error.Code, $"Evidence {evidenceId}: {error.Message}");
                    entry["inclusion"] = new JsonObject { ["status"] = "INVALID", ["reasonCode"] = error.Code };
                }
            }
            evidenceResults.Add(entry);
        }

        // -- Anchors ---------------------------------------------------------
        var anchorsDimension = new JsonObject { ["checkpoints"] = new JsonObject(), ["trustRegistry"] = new JsonObject(), ["status"] = "ABSENT" };
        bool anyWitnessed = false, anyBindingOnly = false, anyAnchorInvalid = false, anyAnchorPending = false;

        JsonArray CheckAnchors(JsonArray records, string kind, JsonNode subject, string label)
        {
            var results = new JsonArray();
            foreach (var recordNode in records)
            {
                var record = recordNode as JsonObject;
                try
                {
                    if (record is null)
                    {
                        throw new AnchorException("ANCHOR_MALFORMED", "an anchor record must be an object");
                    }
                    var binding = Anchoring.VerifyAnchorBinding(record, subject);
                    if (tsaRoots is null)
                    {
                        anyBindingOnly = true;
                        results.Add(new JsonObject { ["anchorId"] = binding.AnchorId, ["status"] = "BINDING_ONLY", ["genTime"] = binding.GenTime });
                    }
                    else
                    {
                        var blindingNonce = Anchoring.DecodeBase64Url(record["blindingNonce"], "blindingNonce");
                        var outcome = Authority.VerifyTimestampAuthority(
                            Canonical.StringOf((JsonObject)record["receipt"]!, "token")!,
                            tsaRoots,
                            Anchoring.AnchorInput(kind, blindingNonce, subject),
                            tsaPolicyOids);
                        anyWitnessed = true;
                        results.Add(new JsonObject
                        {
                            ["anchorId"] = binding.AnchorId,
                            ["status"] = "WITNESSED",
                            ["genTime"] = outcome.GenTime,
                            ["policyOid"] = outcome.PolicyOid,
                            ["trustDomain"] = binding.TrustDomain,
                        });
                    }
                }
                catch (AnchorException error)
                {
                    if (error.Code == "ANCHOR_NOT_PRESENT")
                    {
                        anyAnchorPending = true;
                        weak.Add("ANCHOR_NOT_WITNESSED");
                        results.Add(new JsonObject
                        {
                            ["anchorId"] = record is null ? null : Canonical.StringOf(record, "anchorId"),
                            ["status"] = record is null ? "UNKNOWN" : Canonical.StringOf(record, "status"),
                        });
                    }
                    else
                    {
                        anyAnchorInvalid = true;
                        hard.Add("ANCHOR_INVALID");
                        hard.Add(error.Code);
                        Explain(error.Code, $"{label}: {error.Message}");
                        results.Add(new JsonObject
                        {
                            ["anchorId"] = record is null ? null : Canonical.StringOf(record, "anchorId"),
                            ["status"] = "INVALID",
                            ["reasonCode"] = error.Code,
                        });
                    }
                }
            }
            return results;
        }

        if (parts.Anchors["checkpoints"] is JsonObject checkpointAnchors)
        {
            foreach (var pair in checkpointAnchors)
            {
                long.TryParse(pair.Key, out var sequence);
                if (!signedCheckpoints.TryGetValue(sequence, out var signedCheckpoint))
                {
                    weak.Add("ANCHOR_NOT_WITNESSED");
                    Explain("ANCHOR_NOT_WITNESSED", $"The bundle carries anchors for checkpoint {pair.Key} but not that signed checkpoint itself, so they cannot be checked.");
                    continue;
                }
                ((JsonObject)anchorsDimension["checkpoints"]!)[pair.Key] = CheckAnchors(
                    AnchorRecordsOf(pair.Value),
                    "log-checkpoint",
                    new JsonObject
                    {
                        ["checkpoint"] = signedCheckpoint["checkpoint"]!.DeepClone(),
                        ["signature"] = signedCheckpoint["signature"]!.DeepClone(),
                    },
                    $"checkpoint {pair.Key} anchor");
            }
        }
        if (parts.Anchors["trustRegistry"] is JsonObject registryAnchors)
        {
            foreach (var pair in registryAnchors)
            {
                JsonObject? document = null;
                foreach (var candidateNode in parts.TrustRegistry ?? [])
                {
                    if (candidateNode is JsonObject candidate && candidate["manifest"] is JsonObject manifest
                        && Registry.IntegerOf(manifest["registryVersion"])?.ToString() == pair.Key)
                    {
                        document = candidate;
                        break;
                    }
                }
                if (document is null)
                {
                    weak.Add("ANCHOR_NOT_WITNESSED");
                    Explain("ANCHOR_NOT_WITNESSED", $"The bundle carries anchors for trust-registry version {pair.Key} but not that registry document, so they cannot be checked.");
                    continue;
                }
                ((JsonObject)anchorsDimension["trustRegistry"]!)[pair.Key] = CheckAnchors(
                    AnchorRecordsOf(pair.Value),
                    "trust-registry",
                    new JsonObject
                    {
                        ["manifest"] = document["manifest"]!.DeepClone(),
                        ["signatures"] = document["signatures"]!.DeepClone(),
                    },
                    $"trust-registry version {pair.Key} anchor");
            }
        }

        var anyAnchorRecords = ((JsonObject)anchorsDimension["checkpoints"]!).Count > 0 || ((JsonObject)anchorsDimension["trustRegistry"]!).Count > 0;
        if (!anyAnchorRecords)
        {
            weak.Add("ANCHORS_ABSENT");
            if (latestProfile == "PRE_CUSTOMER_DEFAULT")
            {
                weak.Add("COST_GATED_CAPABILITY_ABSENT");
                Explain("COST_GATED_CAPABILITY_ABSENT", "External anchoring is cost-gated and this deployment profile does not run it.");
            }
            anchorsDimension["status"] = "ABSENT";
        }
        else if (anyAnchorInvalid)
        {
            anchorsDimension["status"] = "INVALID";
        }
        else if (anyWitnessed && !anyBindingOnly && !anyAnchorPending)
        {
            anchorsDimension["status"] = "WITNESSED";
        }
        else if (anyBindingOnly)
        {
            weak.Add("ANCHOR_AUTHORITY_NOT_EVALUATED");
            Explain("ANCHOR_AUTHORITY_NOT_EVALUATED", "Anchor bindings were checked, but no timestamp-authority roots were pinned.");
            anchorsDimension["status"] = "BINDING_ONLY";
        }
        else
        {
            anchorsDimension["status"] = "PARTIAL";
        }
        if (anyAnchorRecords && ((JsonObject)anchorsDimension["trustRegistry"]!).Count == 0)
        {
            weak.Add("REGISTRY_NOT_WITNESSED");
        }

        // -- Assurance profile -----------------------------------------------
        if (latestProfile is null && profiles.Count == 1)
        {
            latestProfile = profiles.First();
        }
        JsonObject profileDimension;
        if (profiles.Count == 0)
        {
            profileDimension = new JsonObject { ["status"] = "UNKNOWN", ["declared"] = new JsonArray() };
        }
        else if (profiles.Count == 1)
        {
            profileDimension = new JsonObject { ["status"] = "CONSISTENT", ["declared"] = new JsonArray(profiles.Select(profile => (JsonNode)profile).ToArray()) };
        }
        else
        {
            weak.Add("PROFILE_MIXED");
            Explain("PROFILE_MIXED", $"The material in this bundle was produced under {profiles.Count} different assurance profiles.");
            profileDimension = new JsonObject
            {
                ["status"] = "MIXED",
                ["declared"] = new JsonArray(profiles.OrderBy(profile => profile, StringComparer.Ordinal).Select(profile => (JsonNode)profile).ToArray()),
            };
        }

        // -- Roll-up ---------------------------------------------------------
        var sealStatuses = evidenceResults.Cast<JsonObject>().Select(result => result!["seal"] is JsonObject sealObj ? Canonical.StringOf(sealObj, "status") : null).ToList();
        var sealsStatus = sealStatuses.Any(status => status == "INVALID") ? "INVALID"
            : sealStatuses.Any(status => status is "ABSENT" or "NOT_CHECKED") ? "INCOMPLETE"
            : sealStatuses.Any(status => status == "PARTIAL") ? "PARTIAL"
            : sealStatuses.Count > 0 ? "VALID" : "ABSENT";

        var commitmentStates = evidenceResults.Cast<JsonObject>().Select(result => Canonical.StringOf(result!, "commitment")).ToList();
        var commitmentStatus = commitmentStates.Any(status => status == "MISMATCH") ? "MISMATCH"
            : commitmentStates.Count > 0 && commitmentStates.All(status => status == "MATCHES") ? "MATCHES"
            : commitmentStates.Any(status => status is "MATCHES" or "MATCHES_ENVELOPE") ? "PARTIAL"
            : "NOT_CHECKED";

        var inclusionStates = evidenceResults.Cast<JsonObject>().Select(result => result!["inclusion"] is JsonObject inclusionObj ? Canonical.StringOf(inclusionObj, "status") : null).ToList();
        var inclusionStatus = inclusionStates.Any(status => status == "INVALID") ? "INVALID"
            : inclusionStates.Count > 0 && inclusionStates.All(status => status == "PROVEN") ? "PROVEN"
            : inclusionStates.Any(status => status is "PROVEN" or "PROVEN_AGAINST_UNVERIFIED_CHECKPOINT") ? "PARTIAL"
            : "ABSENT";

        string[] unsupportedCodes =
        [
            "UNKNOWN_SUITE", "UNKNOWN_ENVELOPE_VERSION", "UNKNOWN_COMMITMENT_VERSION",
            "UNKNOWN_DIGEST_SUITE", "UNKNOWN_KEY_USE", "UNSUPPORTED_KIND", "ANCHOR_SUITE_UNSUPPORTED",
        ];
        var suiteSupportStatus = unsupportedCodes.Any(code => hard.Contains(code) || weak.Contains(code)) ? "UNSUPPORTED" : "SUPPORTED";

        var verdict = hard.Count > 0 ? "NOT_VERIFIED" : weak.Count > 0 ? "PARTIALLY_VERIFIED" : "FULLY_VERIFIED";
        var reasonCodes = new SortedSet<string>(StringComparer.Ordinal);
        reasonCodes.UnionWith(hard);
        reasonCodes.UnionWith(weak);
        reasonCodes.UnionWith(info);

        return new JsonObject
        {
            ["verifierFormatVersion"] = "1",
            ["verdict"] = verdict,
            ["reasonCodes"] = new JsonArray(reasonCodes.Select(code => (JsonNode)code).ToArray()),
            ["explanations"] = explanations,
            ["dimensions"] = new JsonObject
            {
                ["packet"] = packetDimension,
                ["commitment"] = new JsonObject { ["status"] = commitmentStatus },
                ["seals"] = new JsonObject { ["status"] = sealsStatus },
                ["trustRegistry"] = registryDimension,
                ["logInclusion"] = new JsonObject { ["status"] = inclusionStatus },
                ["logConsistency"] = consistencyDimension,
                ["checkpoints"] = checkpointDimension,
                ["anchors"] = anchorsDimension,
                ["assuranceProfile"] = profileDimension,
                ["suiteSupport"] = new JsonObject { ["status"] = suiteSupportStatus },
                ["retention"] = new JsonObject { ["status"] = parts.Packet is null ? "PROOF_ONLY" : "PAYLOAD_PRESENT" },
            },
            ["evidence"] = evidenceResults,
            ["state"] = new JsonObject
            {
                ["registry"] = registry is not null ? registry.State.DeepClone() : state?["registry"]?.DeepClone(),
                ["checkpoint"] = acceptedState?.DeepClone(),
            },
        };
    }
}
