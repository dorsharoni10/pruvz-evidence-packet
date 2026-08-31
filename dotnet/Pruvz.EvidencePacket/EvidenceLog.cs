// Append-only evidence log, format version 1 — independent .NET implementation
// (PRUVZ-97), from docs/EVIDENCE-LOG.md: RFC 6962 / RFC 9162 tree composition
// over domain-separated leaves, signed checkpoints, and the stateful
// acceptance rules.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Pruvz.EvidencePacket;

public sealed class EvidenceLogException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class EvidenceLog
{
    public const string FormatVersion = "1";
    public const string LeafEnvelopeVersion = "1";
    private const string LeafDomainTag = "pruvz.ai/evidence-log-leaf";
    private const string CheckpointDomainTag = "pruvz.ai/log-checkpoint";
    private const char Separator = '\u0000';
    private const long MaxSafeInteger = 9007199254740991;
    private const int MaxBoundTextLength = 512;

    public static readonly string[] AssuranceProfiles = ["PRE_CUSTOMER_DEFAULT", "CUSTOMER_PRODUCTION"];
    private static readonly Regex HexPattern = new("^[0-9a-f]{64}$", RegexOptions.Compiled);
    private static readonly Regex RootHashPattern = new("^sha256:[0-9a-f]{64}$", RegexOptions.Compiled);
    private static readonly Regex PrintableAscii = new("^[\\x20-\\x7e]+$", RegexOptions.Compiled);

    private static EvidenceLogException Refuse(string code, string message) => new(code, message);

    private static byte[] CanonicalBytes(JsonNode? document, string context)
    {
        try
        {
            return Canonical.Canonicalize(document);
        }
        catch (CommitmentException error)
        {
            throw Refuse("LOG_MALFORMED", $"{context} cannot be canonicalized: {error.Message}");
        }
    }

    private static byte[] Sha256(params byte[][] parts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var part in parts)
        {
            hash.AppendData(part);
        }
        return hash.GetHashAndReset();
    }

    private static byte[] HashFromHex(JsonNode? node, string field) => HashFromHex(Registry.AsString(node), field);

    private static byte[] HashFromHex(string? value, string field)
    {
        if (value is null || !HexPattern.IsMatch(value))
        {
            throw Refuse("LOG_MALFORMED", $"{field} must be 64 lowercase hex digits of SHA-256");
        }
        return Convert.FromHexString(value);
    }

    private static byte[] DecodeSignature(JsonNode? node, string field)
    {
        try
        {
            return Registry.DecodeBase64Url(node, field, "MALFORMED_SIGNATURE");
        }
        catch (TrustRegistryException error)
        {
            throw Refuse("MALFORMED_SIGNATURE", error.Message);
        }
    }

    private static string BoundText(JsonNode? node, string field)
    {
        var value = Registry.AsString(node);
        if (string.IsNullOrEmpty(value))
        {
            throw Refuse("LOG_MALFORMED", $"{field} is required");
        }
        if (value.Length > MaxBoundTextLength)
        {
            throw Refuse("LOG_MALFORMED", $"{field} must not exceed {MaxBoundTextLength} characters");
        }
        if (!PrintableAscii.IsMatch(value))
        {
            throw Refuse("LOG_MALFORMED", $"{field} must be printable ASCII");
        }
        return value;
    }

    private static long SafePositiveInteger(JsonNode? node, string field)
    {
        var value = Registry.IntegerOf(node);
        var isNumber = node is JsonValue leaf && leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.Number
            || node is JsonValue direct && direct.TryGetValue<long>(out _);
        if (!isNumber || value is null || value < 1 || value > MaxSafeInteger)
        {
            throw Refuse("LOG_MALFORMED", $"{field} must be an integer between 1 and {MaxSafeInteger}");
        }
        return value.Value;
    }

    public static void RequireSupported(string? formatVersion)
    {
        if (formatVersion != FormatVersion)
        {
            throw Refuse("UNKNOWN_LOG_VERSION", $"Unknown evidence-log version \"{formatVersion}\".");
        }
    }

    // -- Leaf encoding -------------------------------------------------------

    public static byte[] LeafInput(JsonNode? node)
    {
        if (node is not JsonObject seal || seal["envelope"] is not JsonObject envelope)
        {
            throw Refuse("LOG_MALFORMED", "a leaf must be { envelope, signature }");
        }
        if (Canonical.StringOf(envelope, "version") != LeafEnvelopeVersion)
        {
            throw Refuse("LOG_MALFORMED", $"a leaf carries an envelope of version {LeafEnvelopeVersion}");
        }
        var signature = DecodeSignature(seal["signature"], "seal.signature");
        var suiteId = envelope["signer"] is JsonObject signer ? Canonical.StringOf(signer, "suite") : null;
        if (suiteId is not null && Registry.Suites.TryGetValue(suiteId, out var suite) && signature.Length != suite.SignatureLength)
        {
            throw Refuse("MALFORMED_SIGNATURE", $"seal.signature is {signature.Length} bytes");
        }
        var unknown = seal.Select(pair => pair.Key).Where(member => member != "envelope" && member != "signature").ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("LOG_MALFORMED", $"a leaf holds exactly envelope and signature; got {string.Join(", ", unknown)}");
        }
        var header = string.Join(Separator, LeafDomainTag, FormatVersion, "");
        return [.. Encoding.UTF8.GetBytes(header), .. CanonicalBytes(seal, "a leaf")];
    }

    public static byte[] LeafHashOf(byte[] input) => Sha256([0x00], input);

    public static string SealLeafHash(JsonNode? seal) =>
        Convert.ToHexString(LeafHashOf(LeafInput(seal))).ToLowerInvariant();

    // -- Tree composition ----------------------------------------------------

    private static byte[] Node(byte[] left, byte[] right) => Sha256([0x01], left, right);

    private static int Split(int n)
    {
        var k = 1;
        while (k * 2 < n)
        {
            k *= 2;
        }
        return k;
    }

    private static byte[] Head(List<byte[]> hashes, int lo, int hi)
    {
        var n = hi - lo;
        if (n == 1)
        {
            return hashes[lo];
        }
        var k = Split(n);
        return Node(Head(hashes, lo, lo + k), Head(hashes, lo + k, hi));
    }

    public static string TreeHead(IEnumerable<string> leafHashes)
    {
        var hashes = leafHashes.Select((value, index) => HashFromHex(value, $"leafHashes[{index}]")).ToList();
        if (hashes.Count == 0)
        {
            return Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
        }
        return Convert.ToHexString(Head(hashes, 0, hashes.Count)).ToLowerInvariant();
    }

    public static void VerifyInclusion(string? leafHash, long? leafIndex, long? treeSize, JsonArray? path, string? rootHash)
    {
        var leaf = HashFromHex(leafHash, "leafHash");
        var root = HashFromHex(rootHash, "rootHash");
        if (leafIndex is null || leafIndex < 0)
        {
            throw Refuse("LOG_MALFORMED", "leafIndex must be a non-negative integer");
        }
        if (treeSize is null || treeSize < 1)
        {
            throw Refuse("LOG_MALFORMED", "treeSize must be a positive integer");
        }
        if (path is null)
        {
            throw Refuse("LOG_MALFORMED", "path must be an array of node hashes");
        }
        var nodes = path.Select((value, index) => HashFromHex(value, $"path[{index}]")).ToList();

        if (leafIndex >= treeSize)
        {
            throw Refuse("INCLUSION_PROOF_INVALID", $"leaf index {leafIndex} does not exist in a tree of {treeSize} leaves");
        }
        var fn = leafIndex.Value;
        var sn = treeSize.Value - 1;
        var r = leaf;
        foreach (var p in nodes)
        {
            if (sn == 0)
            {
                throw Refuse("INCLUSION_PROOF_INVALID", "the path is longer than the tree is deep");
            }
            if (fn % 2 == 1 || fn == sn)
            {
                r = Node(p, r);
                if (fn % 2 == 0)
                {
                    while (fn != 0 && fn % 2 == 0)
                    {
                        fn /= 2;
                        sn /= 2;
                    }
                }
            }
            else
            {
                r = Node(r, p);
            }
            fn /= 2;
            sn /= 2;
        }
        if (sn != 0)
        {
            throw Refuse("INCLUSION_PROOF_INVALID", "the path is shorter than the tree is deep");
        }
        if (!r.AsSpan().SequenceEqual(root))
        {
            throw Refuse("INCLUSION_PROOF_INVALID", "the path does not lead this leaf to this root");
        }
    }

    public static void VerifyConsistency(long? fromSize, string? fromRootHash, long? toSize, string? toRootHash, JsonArray? proof)
    {
        var fromRoot = HashFromHex(fromRootHash, "fromRootHash");
        var toRoot = HashFromHex(toRootHash, "toRootHash");
        if (fromSize is null || fromSize < 1)
        {
            throw Refuse("LOG_MALFORMED", "fromSize must be a positive integer");
        }
        if (toSize is null || toSize < 1)
        {
            throw Refuse("LOG_MALFORMED", "toSize must be a positive integer");
        }
        if (proof is null)
        {
            throw Refuse("LOG_MALFORMED", "proof must be an array of node hashes");
        }
        var nodes = proof.Select((value, index) => HashFromHex(value, $"proof[{index}]")).ToList();

        if (fromSize > toSize)
        {
            throw Refuse("CONSISTENCY_PROOF_INVALID", $"a tree of {toSize} leaves cannot extend a tree of {fromSize}");
        }
        if (fromSize == toSize)
        {
            if (nodes.Count != 0)
            {
                throw Refuse("CONSISTENCY_PROOF_INVALID", "equal sizes take an empty proof");
            }
            if (!fromRoot.AsSpan().SequenceEqual(toRoot))
            {
                throw Refuse("CONSISTENCY_PROOF_INVALID", "two heads at one size disagree — the tree was altered in place");
            }
            return;
        }
        if ((fromSize & (fromSize - 1)) == 0)
        {
            nodes.Insert(0, fromRoot);
        }
        if (nodes.Count == 0)
        {
            throw Refuse("CONSISTENCY_PROOF_INVALID", "the proof is empty");
        }

        var fn = fromSize.Value - 1;
        var sn = toSize.Value - 1;
        while (fn % 2 == 1)
        {
            fn /= 2;
            sn /= 2;
        }
        var fr = nodes[0];
        var sr = nodes[0];
        foreach (var c in nodes.Skip(1))
        {
            if (sn == 0)
            {
                throw Refuse("CONSISTENCY_PROOF_INVALID", "the proof is longer than the new tree is deep");
            }
            if (fn % 2 == 1 || fn == sn)
            {
                fr = Node(c, fr);
                sr = Node(c, sr);
                if (fn % 2 == 0)
                {
                    while (fn != 0 && fn % 2 == 0)
                    {
                        fn /= 2;
                        sn /= 2;
                    }
                }
            }
            else
            {
                sr = Node(sr, c);
            }
            fn /= 2;
            sn /= 2;
        }
        if (sn != 0)
        {
            throw Refuse("CONSISTENCY_PROOF_INVALID", "the proof is shorter than the new tree is deep");
        }
        if (!fr.AsSpan().SequenceEqual(fromRoot))
        {
            throw Refuse("CONSISTENCY_PROOF_INVALID", "the proof does not reproduce the old head");
        }
        if (!sr.AsSpan().SequenceEqual(toRoot))
        {
            throw Refuse("CONSISTENCY_PROOF_INVALID", "the proof does not reproduce the new head");
        }
    }

    // -- Checkpoints ---------------------------------------------------------

    private static readonly string[] CheckpointMembers =
    [
        "assuranceProfile", "checkpointSequence", "issuedAt", "origin", "rootHash", "signer", "treeSize", "version",
    ];
    private static readonly string[] SignerMembers = ["keyId", "provider", "suite"];

    public static JsonObject ValidateCheckpointDocument(JsonNode? node)
    {
        if (node is not JsonObject document)
        {
            throw Refuse("LOG_MALFORMED", "a checkpoint must be an object");
        }
        RequireSupported(Canonical.StringOf(document, "version"));
        var unknown = document.Select(pair => pair.Key).Where(member => !CheckpointMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("LOG_MALFORMED", $"a checkpoint carries {string.Join(", ", unknown)}; the member set is closed");
        }
        var missing = CheckpointMembers.Where(member => !document.ContainsKey(member)).ToList();
        if (missing.Count > 0)
        {
            throw Refuse("LOG_MALFORMED", $"a checkpoint is missing {string.Join(", ", missing)}");
        }
        if (!AssuranceProfiles.Contains(Canonical.StringOf(document, "assuranceProfile")))
        {
            throw Refuse("LOG_MALFORMED", $"assuranceProfile must be one of {string.Join(", ", AssuranceProfiles)}");
        }
        SafePositiveInteger(document["checkpointSequence"], "checkpointSequence");
        SafePositiveInteger(document["treeSize"], "treeSize");
        BoundText(document["origin"], "origin");
        var rootHash = Canonical.StringOf(document, "rootHash");
        if (rootHash is null || !RootHashPattern.IsMatch(rootHash))
        {
            throw Refuse("LOG_MALFORMED", "rootHash must be \"sha256:\" then 64 lowercase hex digits");
        }
        var issuedAt = Canonical.StringOf(document, "issuedAt");
        string? issuedAtCanonical = null;
        if (issuedAt is not null)
        {
            try
            {
                issuedAtCanonical = Canonical.CanonicalTimestamp(issuedAt);
            }
            catch (CommitmentException)
            {
                issuedAtCanonical = null;
            }
        }
        if (issuedAtCanonical != issuedAt || issuedAt is null)
        {
            throw Refuse("LOG_MALFORMED", "issuedAt must be a canonical UTC timestamp");
        }
        if (document["signer"] is not JsonObject signer)
        {
            throw Refuse("LOG_MALFORMED", "signer must be an object");
        }
        var signerUnknown = signer.Select(pair => pair.Key).Where(member => !SignerMembers.Contains(member)).ToList();
        if (signerUnknown.Count > 0)
        {
            throw Refuse("LOG_MALFORMED", $"signer carries {string.Join(", ", signerUnknown)}");
        }
        BoundText(signer["keyId"], "signer.keyId");
        BoundText(signer["provider"], "signer.provider");
        var suite = Canonical.StringOf(signer, "suite");
        if (suite is null || !Registry.Suites.ContainsKey(suite))
        {
            throw Refuse("LOG_MALFORMED", $"signer.suite \"{suite}\" is not a suite this contract defines");
        }
        return document;
    }

    public static byte[] CheckpointSigningInput(JsonNode? node)
    {
        var document = ValidateCheckpointDocument(node);
        var header = string.Join(Separator, CheckpointDomainTag, Canonical.StringOf(document, "version"), "");
        return [.. Encoding.UTF8.GetBytes(header), .. CanonicalBytes(document, "a checkpoint")];
    }

    public static void VerifyCheckpoint(JsonNode? checkpointNode, JsonNode? signatureNode, JsonObject jwk)
    {
        var checkpoint = ValidateCheckpointDocument(checkpointNode);
        var suiteId = Canonical.StringOf((JsonObject)checkpoint["signer"]!, "suite")!;
        var suite = Registry.Suites[suiteId];
        var signatureBytes = DecodeSignature(signatureNode, "signature");
        if (signatureBytes.Length != suite.SignatureLength)
        {
            throw Refuse("MALFORMED_SIGNATURE", $"signature is {signatureBytes.Length} bytes");
        }
        try
        {
            using var key = Registry.LoadPublicKey(jwk, suiteId);
        }
        catch (Exception exception) when (exception is CryptographicException or TrustRegistryException or ArgumentException or InvalidOperationException)
        {
            throw Refuse("INVALID_PUBLIC_KEY", "jwk is not a valid public key");
        }
        if (!Registry.SignatureVerifies(CheckpointSigningInput(checkpoint), jwk, suiteId, signatureBytes))
        {
            throw Refuse("CHECKPOINT_SIGNATURE_INVALID", "the signature over this checkpoint does not verify under this key");
        }
    }

    public static JsonObject AcceptCheckpoint(JsonObject? accepted, JsonNode? candidateNode, JsonArray? consistencyProof)
    {
        var candidate = ValidateCheckpointDocument(candidateNode);
        var state = new JsonObject
        {
            ["checkpointSequence"] = Registry.IntegerOf(candidate["checkpointSequence"])!.Value,
            ["origin"] = Canonical.StringOf(candidate, "origin"),
            ["rootHash"] = Canonical.StringOf(candidate, "rootHash"),
            ["treeSize"] = Registry.IntegerOf(candidate["treeSize"])!.Value,
        };
        if (accepted is null)
        {
            return state;
        }
        BoundText(accepted["origin"], "accepted.origin");
        SafePositiveInteger(accepted["checkpointSequence"], "accepted.checkpointSequence");
        SafePositiveInteger(accepted["treeSize"], "accepted.treeSize");
        var acceptedRoot = Canonical.StringOf(accepted, "rootHash");
        if (acceptedRoot is null || !RootHashPattern.IsMatch(acceptedRoot))
        {
            throw Refuse("LOG_MALFORMED", "accepted.rootHash must be \"sha256:\" then 64 lowercase hex digits");
        }

        var candidateOrigin = Canonical.StringOf(candidate, "origin");
        var acceptedOrigin = Canonical.StringOf(accepted, "origin");
        if (candidateOrigin != acceptedOrigin)
        {
            throw Refuse("CHECKPOINT_ORIGIN_MISMATCH", $"this checkpoint is from log \"{candidateOrigin}\", not \"{acceptedOrigin}\"");
        }
        var candidateSequence = Registry.IntegerOf(candidate["checkpointSequence"])!.Value;
        var acceptedSequence = Registry.IntegerOf(accepted["checkpointSequence"])!.Value;
        var candidateSize = Registry.IntegerOf(candidate["treeSize"])!.Value;
        var acceptedSize = Registry.IntegerOf(accepted["treeSize"])!.Value;
        var candidateRoot = Canonical.StringOf(candidate, "rootHash")!;
        if (candidateSequence < acceptedSequence)
        {
            throw Refuse("CHECKPOINT_STALE", $"checkpoint {candidateSequence} is older than the already accepted {acceptedSequence}");
        }
        if (candidateSequence == acceptedSequence)
        {
            if (candidateSize == acceptedSize && candidateRoot == acceptedRoot)
            {
                return state;
            }
            throw Refuse("CHECKPOINT_FORK", $"two checkpoints numbered {candidateSequence} disagree — the log presented two histories");
        }
        if (candidateSize < acceptedSize)
        {
            throw Refuse("CHECKPOINT_ROLLBACK", $"checkpoint {candidateSequence} covers {candidateSize} leaves but {acceptedSequence} already covered {acceptedSize}");
        }
        if (candidateSize == acceptedSize)
        {
            if (candidateRoot != acceptedRoot)
            {
                throw Refuse("CHECKPOINT_FORK", "a later checkpoint at the same tree size names a different head");
            }
            return state;
        }
        VerifyConsistency(
            acceptedSize,
            acceptedRoot["sha256:".Length..],
            candidateSize,
            candidateRoot["sha256:".Length..],
            consistencyProof ?? []);
        return state;
    }
}
