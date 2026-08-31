// The .NET conformance harness (PRUVZ-97).
//
// Replays every published vector — the four layer packs, the verifier/v1
// golden cases and the conformance/v1 adversarial suite — through the
// independent .NET implementation, and emits the same normalized results
// document as the Node and Python harnesses. It NEVER reads a vector's
// expectation to produce an answer; bin/conformance-compare.mjs is the one
// place expectations are read.
//
// Usage: dotnet run --project conformance/dotnet -- <repo-root> <out-file.json>

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using PruvzConformance;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: dotnet run --project conformance/dotnet -- <repo-root> <out-file.json>");
    return 2;
}
var repoRoot = args[0];
var outFile = args[1];
Validator.SchemaRoot = Path.Combine(repoRoot, "schema");

static JsonNode? ParseStrict(string text)
{
    var node = JsonNode.Parse(text);
    AssertUniqueMembers(node);
    return node;
}

static void AssertUniqueMembers(JsonNode? node)
{
    // System.Text.Json's JsonNode.Parse throws for duplicate properties only
    // via JsonObject materialization; walking forces it everywhere.
    switch (node)
    {
        case JsonObject obj:
            foreach (var pair in obj)
            {
                AssertUniqueMembers(pair.Value);
            }
            break;
        case JsonArray array:
            foreach (var item in array)
            {
                AssertUniqueMembers(item);
            }
            break;
    }
}

JsonObject LoadVectors(string name) =>
    (JsonObject)ParseStrict(File.ReadAllText(Path.Combine(repoRoot, name, "v1", "golden-vectors.json")))!;

var commitmentVectors = LoadVectors("commitment");
var registryVectors = LoadVectors("trust-registry");
var logVectors = LoadVectors("evidence-log");
var anchoringVectors = LoadVectors("anchoring");
var verifierVectors = LoadVectors("verifier");
var conformanceVectors = LoadVectors("conformance");

static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

static string? CodeOf(Action action)
{
    try
    {
        action();
        return null;
    }
    catch (CommitmentException error) { return error.Code; }
    catch (TrustRegistryException error) { return error.Code; }
    catch (EvidenceLogException error) { return error.Code; }
    catch (AnchorException error) { return error.Code; }
}

static JsonObject NormalizeReport(JsonObject report)
{
    var dimensions = new JsonObject();
    foreach (var pair in (JsonObject)report["dimensions"]!)
    {
        dimensions[pair.Key] = Canonical.StringOf((JsonObject)pair.Value!, "status") ?? "COMPOSITE";
    }
    var reasonCodes = ((JsonArray)report["reasonCodes"]!).Select(code => (string)code!).OrderBy(code => code, StringComparer.Ordinal);
    return new JsonObject
    {
        ["outcome"] = "REPORT",
        ["verdict"] = Canonical.StringOf(report, "verdict"),
        ["reasonCodes"] = new JsonArray(reasonCodes.Select(code => (JsonNode)code).ToArray()),
        ["dimensions"] = dimensions,
        ["state"] = report["state"]!.DeepClone(),
    };
}

// -- commitment/v1 -----------------------------------------------------------

JsonObject RunCommitment()
{
    var outDecimals = new JsonArray();
    foreach (var vector in (JsonArray)commitmentVectors["decimals"]!)
    {
        outDecimals.Add((JsonNode)Canonical.CanonicalDecimal(Canonical.StringOf((JsonObject)vector!, "input")!));
    }
    var outTimestamps = new JsonArray();
    foreach (var vector in (JsonArray)commitmentVectors["timestamps"]!)
    {
        outTimestamps.Add((JsonNode)Canonical.CanonicalTimestamp(Canonical.StringOf((JsonObject)vector!, "input")));
    }
    var outCanonicalization = new JsonObject();
    foreach (var vectorNode in (JsonArray)commitmentVectors["canonicalization"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var document = vector.ContainsKey("documentJson")
            ? ParseStrict(Canonical.StringOf(vector, "documentJson")!)
            : vector["document"];
        outCanonicalization[Canonical.StringOf(vector, "id")!] =
            System.Text.Encoding.UTF8.GetString(Canonical.Canonicalize(document));
    }
    var outCommitments = new JsonObject();
    foreach (var vectorNode in (JsonArray)commitmentVectors["commitments"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var kind = Canonical.StringOf(vector, "kind")!;
        var document = kind == "evidence-item"
            ? Canonical.EvidenceItemDocument((JsonObject)vector["source"]!)
            : Canonical.EvidencePacketDocument((JsonObject)vector["source"]!);
        outCommitments[Canonical.StringOf(vector, "id")!] = new JsonObject
        {
            ["canonical"] = System.Text.Encoding.UTF8.GetString(Canonical.Canonicalize(document)),
            ["digest"] = Canonical.CommitmentDigest(kind, document),
        };
    }
    var outRejected = new JsonObject();
    foreach (var vectorNode in (JsonArray)commitmentVectors["rejected"]!)
    {
        var vector = (JsonObject)vectorNode!;
        outRejected[Canonical.StringOf(vector, "id")!] = CodeOf(() => RejectOne(vector));
    }
    return new JsonObject
    {
        ["decimals"] = outDecimals,
        ["timestamps"] = outTimestamps,
        ["canonicalization"] = outCanonicalization,
        ["commitments"] = outCommitments,
        ["rejected"] = outRejected,
    };
}

void RejectOne(JsonObject vector)
{
    var document = vector.ContainsKey("documentJson")
        ? ParseStrict(Canonical.StringOf(vector, "documentJson")!)
        : vector["document"]?.DeepClone();
    switch (Canonical.StringOf(vector, "layer"))
    {
        case "decimal":
            Canonical.CanonicalDecimal(Canonical.StringOf(vector, "input")!);
            break;
        case "timestamp":
            Canonical.CanonicalTimestamp(Canonical.StringOf(vector, "input"));
            break;
        case "canonicalization":
            Canonical.Canonicalize(document);
            break;
        case "commitment":
            Canonical.CommitmentDigest(Canonical.StringOf(vector, "kind")!, document);
            break;
        case "digest":
            Canonical.CommitmentDigest(Canonical.StringOf(vector, "kind")!, document, Canonical.StringOf(vector, "suite"));
            break;
        case "supported":
            Canonical.RequireSupported(Canonical.StringOf(vector, "commitmentVersion"), Canonical.StringOf(vector, "suite"));
            break;
        case "evidence-item-document":
            Canonical.EvidenceItemDocument((JsonObject)vector["source"]!);
            break;
        case "evidence-packet-document":
            Canonical.EvidencePacketDocument((JsonObject)vector["source"]!);
            break;
        default:
            throw new InvalidOperationException($"unknown rejected-vector layer \"{Canonical.StringOf(vector, "layer")}\"");
    }
}

// -- trust-registry/v1 -------------------------------------------------------

JsonObject RunTrustRegistry()
{
    var outThumbprints = new JsonObject();
    foreach (var vectorNode in (JsonArray)registryVectors["thumbprints"]!)
    {
        var vector = (JsonObject)vectorNode!;
        outThumbprints[Canonical.StringOf(vector, "id")!] = Registry.JwkThumbprint(vector["jwk"]);
    }
    var allDocuments = new JsonObject();
    foreach (var pair in (JsonObject)registryVectors["documents"]!)
    {
        allDocuments[pair.Key] = pair.Value!.DeepClone();
    }
    foreach (var pair in (JsonObject)registryVectors["badDocuments"]!)
    {
        allDocuments[pair.Key] = pair.Value!.DeepClone();
    }
    var outDigests = new JsonObject();
    foreach (var pair in (JsonObject)registryVectors["digests"]!)
    {
        var manifest = (JsonObject)((JsonObject)allDocuments[pair.Key]!)["manifest"]!;
        outDigests[pair.Key] = Registry.ManifestDigest(manifest);
    }
    var pin = (JsonObject)registryVectors["pin"]!;
    var outChainCases = new JsonObject();
    foreach (var scenarioNode in (JsonArray)registryVectors["chainCases"]!)
    {
        var scenario = (JsonObject)scenarioNode!;
        var casePin = scenario.ContainsKey("pinOverride") ? scenario["pinOverride"] as JsonObject : pin;
        JsonObject outcome;
        try
        {
            JsonObject? chainState = null;
            foreach (var idNode in (JsonArray)scenario["establish"]!)
            {
                var establishDocuments = new JsonArray(allDocuments[(string)idNode!]!.DeepClone());
                chainState = Registry.AcceptChain(establishDocuments, pin, chainState).State;
            }
            var attemptDocuments = new JsonArray(
                ((JsonArray)scenario["attempt"]!).Select(idNode => allDocuments[(string)idNode!]!.DeepClone()).ToArray());
            // A null pinOverride is the published no-pin case.
            var accepted = Registry.AcceptChain(attemptDocuments, casePin ?? new JsonObject(), chainState);
            outcome = new JsonObject
            {
                ["outcome"] = "ACCEPT",
                ["registryVersion"] = Registry.IntegerOf(accepted.State["registryVersion"])!.Value,
                ["digest"] = Canonical.StringOf(accepted.State, "digest"),
            };
        }
        catch (TrustRegistryException error)
        {
            outcome = new JsonObject { ["outcome"] = "REFUSE", ["code"] = error.Code };
        }
        outChainCases[Canonical.StringOf(scenario, "id")!] = outcome;
    }
    var outRefusalCases = new JsonObject();
    foreach (var scenarioNode in (JsonArray)registryVectors["refusalCases"]!)
    {
        var scenario = (JsonObject)scenarioNode!;
        outRefusalCases[Canonical.StringOf(scenario, "id")!] = CodeOf(() =>
            Registry.VerifyManifest(allDocuments[Canonical.StringOf(scenario, "document")!], pin));
    }
    var outSealCases = new JsonObject();
    foreach (var scenarioNode in (JsonArray)registryVectors["sealCases"]!)
    {
        var scenario = (JsonObject)scenarioNode!;
        var manifest = Registry.VerifyManifest(
            ((JsonObject)registryVectors["documents"]!)[Canonical.StringOf(scenario, "registry")!], pin).Manifest;
        var digestRef = scenario["commitmentDigest"];
        var result = Registry.VerifySeal(
            (JsonObject)((JsonObject)registryVectors["seals"]!)[Canonical.StringOf(scenario, "seal")!]!,
            manifest,
            (JsonObject)((JsonObject)registryVectors["subjects"]!)[Canonical.StringOf(scenario, "subject")!]!,
            digestRef is null ? null : Canonical.StringOf((JsonObject)registryVectors["expectedCommitmentDigests"]!, (string)digestRef!),
            []);
        outSealCases[Canonical.StringOf(scenario, "id")!] = new JsonObject
        {
            ["verdict"] = result.Verdict,
            ["reasonCodes"] = new JsonArray(result.ReasonCodes.OrderBy(code => code, StringComparer.Ordinal).Select(code => (JsonNode)code).ToArray()),
            ["dimensions"] = new JsonObject(result.Dimensions.Select(pair => KeyValuePair.Create<string, JsonNode?>(pair.Key, pair.Value))),
        };
    }
    return new JsonObject
    {
        ["thumbprints"] = outThumbprints,
        ["digests"] = outDigests,
        ["chainCases"] = outChainCases,
        ["refusalCases"] = outRefusalCases,
        ["sealCases"] = outSealCases,
    };
}

// -- evidence-log/v1 ---------------------------------------------------------

JsonObject RunEvidenceLog()
{
    var known = (JsonObject)logVectors["rfc6962KnownAnswers"]!;
    var knownHashes = ((JsonArray)known["leafDataHex"]!)
        .Select(hex => Convert.ToHexString(EvidenceLog.LeafHashOf(Convert.FromHexString((string)hex!))).ToLowerInvariant())
        .ToList();
    var rfcRoots = knownHashes.Select((_, index) => EvidenceLog.TreeHead(knownHashes.Take(index + 1))).ToList();

    var outLeafInputSha256 = new JsonObject();
    var leafHashes = new List<string>();
    foreach (var pair in (JsonObject)logVectors["seals"]!)
    {
        outLeafInputSha256[pair.Key] = Sha256Hex(EvidenceLog.LeafInput(pair.Value));
        leafHashes.Add(EvidenceLog.SealLeafHash(pair.Value));
    }
    var treeRoots = leafHashes.Select((_, index) => EvidenceLog.TreeHead(leafHashes.Take(index + 1))).ToList();

    var outInclusion = new JsonArray();
    foreach (var vectorNode in (JsonArray)((JsonObject)logVectors["tree"]!)["inclusion"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var leafIndex = (int)Registry.IntegerOf(vector["leafIndex"])!.Value;
        var treeSize = (int)Registry.IntegerOf(vector["treeSize"])!.Value;
        outInclusion.Add((JsonNode)(CodeOf(() => EvidenceLog.VerifyInclusion(
            leafHashes[leafIndex], leafIndex, treeSize, (JsonArray)vector["path"]!, treeRoots[treeSize - 1])) ?? "VERIFIED"));
    }
    var outConsistency = new JsonArray();
    foreach (var vectorNode in (JsonArray)((JsonObject)logVectors["tree"]!)["consistency"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var fromSize = (int)Registry.IntegerOf(vector["fromSize"])!.Value;
        var toSize = (int)Registry.IntegerOf(vector["toSize"])!.Value;
        outConsistency.Add((JsonNode)(CodeOf(() => EvidenceLog.VerifyConsistency(
            fromSize, treeRoots[fromSize - 1], toSize, treeRoots[toSize - 1], (JsonArray)vector["proof"]!)) ?? "VERIFIED"));
    }

    var outCheckpointInputs = new JsonObject();
    var signingKey = (JsonObject)((JsonObject)logVectors["signingKey"]!)["jwk"]!;
    foreach (var pair in (JsonObject)logVectors["checkpoints"]!)
    {
        var entry = (JsonObject)pair.Value!;
        EvidenceLog.VerifyCheckpoint(entry["checkpoint"], entry["signature"], signingKey);
        outCheckpointInputs[pair.Key] = Sha256Hex(EvidenceLog.CheckpointSigningInput(entry["checkpoint"]));
    }

    var outAcceptance = new JsonArray();
    JsonObject? accepted = null;
    foreach (var stepNode in (JsonArray)((JsonObject)logVectors["acceptanceChain"]!)["steps"]!)
    {
        var step = (JsonObject)stepNode!;
        var candidate = ((JsonObject)((JsonObject)logVectors["checkpoints"]!)[Canonical.StringOf(step, "candidate")!]!)["checkpoint"]!;
        accepted = EvidenceLog.AcceptCheckpoint(accepted, candidate, step["consistencyProof"] as JsonArray);
        outAcceptance.Add(new JsonObject
        {
            ["candidate"] = Canonical.StringOf(step, "candidate"),
            ["treeSize"] = Registry.IntegerOf(accepted["treeSize"])!.Value,
            ["rootHash"] = Canonical.StringOf(accepted, "rootHash"),
        });
    }

    var outRefusals = new JsonObject();
    foreach (var refusalNode in (JsonArray)logVectors["refusals"]!)
    {
        var refusal = (JsonObject)refusalNode!;
        outRefusals[Canonical.StringOf(refusal, "id")!] = CodeOf(() => ReplayLogRefusal(refusal, signingKey));
    }
    return new JsonObject
    {
        ["rfc6962LeafHashes"] = new JsonArray(knownHashes.Select(hash => (JsonNode)hash).ToArray()),
        ["rfc6962RootsBySize"] = new JsonArray(rfcRoots.Select(root => (JsonNode)root).ToArray()),
        ["leafInputSha256"] = outLeafInputSha256,
        ["leafHashes"] = new JsonArray(leafHashes.Select(hash => (JsonNode)hash).ToArray()),
        ["treeRootsBySize"] = new JsonArray(treeRoots.Select(root => (JsonNode)root).ToArray()),
        ["inclusion"] = outInclusion,
        ["consistency"] = outConsistency,
        ["checkpointSigningInputSha256"] = outCheckpointInputs,
        ["acceptanceChain"] = outAcceptance,
        ["refusals"] = outRefusals,
    };
}

void ReplayLogRefusal(JsonObject refusal, JsonObject signingKey)
{
    switch (Canonical.StringOf(refusal, "kind"))
    {
        case "validateCheckpoint":
            EvidenceLog.ValidateCheckpointDocument(refusal["document"]);
            break;
        case "leaf":
            EvidenceLog.LeafInput(refusal["seal"]);
            break;
        case "inclusion":
        {
            var leafHash = refusal.ContainsKey("tamperedSeal")
                ? EvidenceLog.SealLeafHash(refusal["tamperedSeal"])
                : Canonical.StringOf(refusal, "leafHash");
            EvidenceLog.VerifyInclusion(
                leafHash,
                Registry.IntegerOf(refusal["leafIndex"]),
                Registry.IntegerOf(refusal["treeSize"]),
                refusal["path"] as JsonArray,
                Canonical.StringOf(refusal, "rootHashHex"));
            break;
        }
        case "consistency":
            EvidenceLog.VerifyConsistency(
                Registry.IntegerOf(refusal["fromSize"]),
                Canonical.StringOf(refusal, "fromRootHash"),
                Registry.IntegerOf(refusal["toSize"]),
                Canonical.StringOf(refusal, "toRootHash"),
                refusal["proof"] as JsonArray);
            break;
        case "verifyCheckpoint":
            EvidenceLog.VerifyCheckpoint(
                refusal["checkpoint"], refusal["signature"], refusal["jwk"] as JsonObject ?? signingKey);
            break;
        case "acceptance":
            EvidenceLog.AcceptCheckpoint(
                refusal["accepted"] as JsonObject, refusal["candidate"], refusal["consistencyProof"] as JsonArray);
            break;
        default:
            throw new InvalidOperationException($"unknown refusal kind \"{Canonical.StringOf(refusal, "kind")}\"");
    }
}

// -- anchoring/v1 ------------------------------------------------------------

JsonObject MaterializeRecord(JsonObject record)
{
    var clone = (JsonObject)record.DeepClone();
    if (clone["receipt"] is JsonObject receipt && Canonical.StringOf(receipt, "token") is { } token && token.StartsWith('@'))
    {
        receipt["token"] = Canonical.StringOf((JsonObject)anchoringVectors["receipts"]!, token[1..]);
    }
    return clone;
}

JsonObject RunAnchoring()
{
    var subjects = (JsonObject)anchoringVectors["subjects"]!;
    var outDeterministic = new JsonObject();
    foreach (var vectorNode in (JsonArray)anchoringVectors["deterministic"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var subject = subjects[Canonical.StringOf(vector, "subjectRef")!]!;
        var kind = subject is JsonObject subjectObj && subjectObj.ContainsKey("checkpoint") ? "log-checkpoint" : "trust-registry";
        var nonce = Anchoring.DecodeBase64Url(vector["blindingNonce"], "blindingNonce");
        var input = Anchoring.AnchorInput(kind, nonce, subject);
        outDeterministic[Canonical.StringOf(vector, "id")!] = new JsonObject
        {
            ["anchorInputLength"] = input.Length,
            ["anchorInputSha256"] = Sha256Hex(input),
            ["imprint"] = Convert.ToHexString(Anchoring.AnchorImprint(kind, nonce, subject)).ToLowerInvariant(),
        };
    }
    var outBindingCases = new JsonObject();
    foreach (var vectorNode in (JsonArray)anchoringVectors["bindingCases"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var record = MaterializeRecord((JsonObject)vector["record"]!);
        var binding = Anchoring.VerifyAnchorBinding(record, subjects[Canonical.StringOf(vector, "subjectRef")!]);
        outBindingCases[Canonical.StringOf(vector, "id")!] = new JsonObject
        {
            ["genTime"] = binding.GenTime,
            ["policyOid"] = binding.PolicyOid,
            ["imprint"] = binding.Imprint,
        };
    }
    var outRefusals = new JsonObject();
    foreach (var vectorNode in (JsonArray)anchoringVectors["refusals"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var record = MaterializeRecord((JsonObject)vector["record"]!);
        var subject = subjects[Canonical.StringOf(vector, "subjectRef")!];
        outRefusals[Canonical.StringOf(vector, "id")!] = CodeOf(() => Anchoring.VerifyAnchorBinding(record, subject));
    }
    var outDivergence = new JsonObject();
    foreach (var vectorNode in (JsonArray)anchoringVectors["runtimeDivergence"]!)
    {
        var vector = (JsonObject)vectorNode!;
        var record = MaterializeRecord((JsonObject)vector["record"]!);
        var subject = subjects[Canonical.StringOf(vector, "subjectRef")!];
        var binds = CodeOf(() => Anchoring.VerifyAnchorBinding(record, subject)) is null;
        var token = Canonical.StringOf((JsonObject)record["receipt"]!, "token")!;
        // The pinned root for the replay is the token's self-signed certificate —
        // chosen by identity, not by position: embedded-certificate order is a
        // platform detail no vector may depend on.
        var chain = Authority.EmbeddedCertificates(token);
        var root = chain.FirstOrDefault(pem =>
        {
            var certificate = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(pem);
            return certificate.Subject == certificate.Issuer;
        }) ?? chain[^1];
        string? halfTwoCode = null;
        try
        {
            var recordSubject = (JsonObject)record["subject"]!;
            Authority.VerifyTimestampAuthority(
                token,
                [root],
                Anchoring.AnchorInput(
                    Canonical.StringOf(recordSubject, "kind")!,
                    Anchoring.DecodeBase64Url(record["blindingNonce"], "blindingNonce"),
                    subject));
        }
        catch (AnchorException error)
        {
            halfTwoCode = error.Code;
        }
        outDivergence[Canonical.StringOf(vector, "id")!] = new JsonObject { ["binds"] = binds, ["halfTwoCode"] = halfTwoCode };
    }
    return new JsonObject
    {
        ["deterministic"] = outDeterministic,
        ["bindingCases"] = outBindingCases,
        ["refusals"] = outRefusals,
        ["runtimeDivergence"] = outDivergence,
    };
}

// -- verifier/v1 and conformance/v1 ------------------------------------------

static List<string> PemList(JsonNode? node) =>
    node is JsonArray array ? array.Select(item => (string)item!).ToList() : [];

JsonObject RunVerifierCases()
{
    var output = new JsonObject();
    foreach (var caseNode in (JsonArray)verifierVectors["cases"]!)
    {
        var goldenCase = (JsonObject)caseNode!;
        var options = (JsonObject)goldenCase["options"]!;
        var pin = (JsonObject)verifierVectors["pin"]!;
        if (Canonical.StringOf(options, "pinRootOverride") is { } pinOverride)
        {
            pin = new JsonObject { ["issuer"] = Canonical.StringOf(pin, "issuer"), ["root"] = pinOverride };
        }
        var report = Verify.VerifyBundle(
            ((JsonObject)verifierVectors["bundles"]!)[Canonical.StringOf(goldenCase, "bundle")!]!.DeepClone(),
            pin,
            Canonical.StringOf(options, "tenant"),
            options["tsaRoots"] is JsonValue tsaFlag && tsaFlag.TryGetValue<bool>(out var useTsa) && useTsa
                ? PemList(verifierVectors["tsaRoots"])
                : null,
            null,
            null);
        output[Canonical.StringOf(goldenCase, "id")!] = NormalizeReport(report);
    }
    return output;
}

JsonObject RunConformanceCases()
{
    var output = new JsonObject();
    foreach (var caseNode in (JsonArray)conformanceVectors["cases"]!)
    {
        var conformanceCase = (JsonObject)caseNode!;
        var results = new JsonArray();
        JsonObject? heldState = null;
        foreach (var stepNode in (JsonArray)conformanceCase["steps"]!)
        {
            var step = (JsonObject)stepNode!;
            var rawText = step.ContainsKey("rawBundle")
                ? Canonical.StringOf((JsonObject)conformanceVectors["rawBundles"]!, Canonical.StringOf(step, "rawBundle")!)!
                : ((JsonObject)conformanceVectors["bundles"]!)[Canonical.StringOf(step, "bundle")!]!.ToJsonString();
            JsonNode? bundle;
            try
            {
                bundle = ParseStrict(rawText);
            }
            catch (Exception error) when (error is JsonException or ArgumentException)
            {
                results.Add(new JsonObject { ["outcome"] = "UNUSABLE_INPUT" });
                continue;
            }
            var options = (JsonObject)step["options"]!;
            IReadOnlyList<string>? tsaRoots = null;
            if (options["tsaRoots"] is JsonValue tsaValue)
            {
                if (tsaValue.TryGetValue<bool>(out var useTsa) && useTsa)
                {
                    tsaRoots = PemList(conformanceVectors["tsaRoots"]);
                }
                else if (tsaValue.TryGetValue<string>(out var mode) && mode == "wrong")
                {
                    tsaRoots = PemList(conformanceVectors["wrongTsaRoots"]);
                }
            }
            try
            {
                var report = Verify.VerifyBundle(
                    bundle,
                    (JsonObject)conformanceVectors["pin"]!,
                    Canonical.StringOf(options, "tenant"),
                    tsaRoots,
                    null,
                    Canonical.StringOf(options, "state") == "held" ? heldState : null);
                heldState = (JsonObject)report["state"]!.DeepClone();
                results.Add(NormalizeReport(report));
            }
            catch (VerifierException)
            {
                results.Add(new JsonObject { ["outcome"] = "UNUSABLE_INPUT" });
            }
        }
        output[Canonical.StringOf(conformanceCase, "id")!] = results;
    }
    return output;
}

var resultsDocument = new JsonObject
{
    ["harnessResultsVersion"] = "1",
    ["runtime"] = "dotnet",
    ["layers"] = new JsonObject
    {
        ["commitment"] = RunCommitment(),
        ["trustRegistry"] = RunTrustRegistry(),
        ["evidenceLog"] = RunEvidenceLog(),
        ["anchoring"] = RunAnchoring(),
    },
    ["verifierV1"] = RunVerifierCases(),
    ["conformance"] = RunConformanceCases(),
};

// The results directory is generated output and is not in git, so a fresh
// clone has to create it before the first harness writes into it.
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outFile))!);
File.WriteAllText(outFile, resultsDocument.ToJsonString(new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
}) + "\n");
Console.WriteLine($"dotnet harness: wrote {outFile}");
return 0;

