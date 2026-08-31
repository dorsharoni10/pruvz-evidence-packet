// Public Trust Registry, format version 1 — independent .NET implementation
// (PRUVZ-97), from docs/TRUST-REGISTRY.md. ECDSA verification is the
// platform's ECDsa over IEEE P1363 signatures; nothing cryptographic is
// implemented here.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace PruvzConformance;

public sealed class TrustRegistryException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record RegistryKey(
    string KeyId, string? PredecessorKeyId, string Provider, JsonObject PublicKey,
    string? RetiredAtUtc, string? RevocationReason, string? RevokedAtUtc,
    string Status, string Suite, string Thumbprint, string Use, string ValidFromUtc);

public sealed record ValidatedManifest(
    string FormatVersion, string IssuedAtUtc, string Issuer, List<RegistryKey> Keys,
    JsonObject? Previous, long RegistryVersion, JsonObject Raw);

public sealed record ManifestSignature(string KeyId, byte[] Signature, RegistryKey Signer, string Suite);

public sealed record VerifiedManifest(
    JsonNode? Attestations, string Digest, ValidatedManifest Manifest, string RootKeyId, string RootStatus);

public sealed record SealVerdict(Dictionary<string, string> Dimensions, List<string> ReasonCodes, string Verdict);

public static class Registry
{
    public const string FormatVersion = "1";
    public const string SealEnvelopeVersion = "1";

    private const string RegistryDomainTag = "pruvz.ai/trust-registry";
    private const string SealDomainTag = "pruvz.ai/evidence-signature";
    private const char Separator = '\u0000';
    private const int MaxTextLength = 512;

    public static readonly Dictionary<string, (string Curve, HashAlgorithmName Hash, int CoordinateLength, int SignatureLength)> Suites = new()
    {
        ["ES256"] = ("P-256", HashAlgorithmName.SHA256, 32, 64),
        ["ES384"] = ("P-384", HashAlgorithmName.SHA384, 48, 96),
    };

    private static readonly string[] JwkMembers = ["crv", "kty", "x", "y"];
    private static readonly string[] KeyMembers =
    [
        "keyId", "predecessorKeyId", "provider", "publicKey", "retiredAtUtc", "revocationReason",
        "revokedAtUtc", "status", "suite", "thumbprint", "use", "validFromUtc",
    ];
    private static readonly string[] ManifestMembers = ["formatVersion", "issuedAtUtc", "issuer", "keys", "previous", "registryVersion"];
    private static readonly string[] KeyUses = ["trust-root", "evidence-signing"];
    private static readonly string[] KeyStatuses = ["ACTIVE", "RETIRED", "REVOKED"];
    private static readonly Regex DigestPattern = new("^sha256:[0-9a-f]{64}$", RegexOptions.Compiled);
    private static readonly Regex Base64UrlPattern = new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);

    private static TrustRegistryException Refuse(string code, string message) => new(code, message);

    private static string Text(JsonNode? node, string field)
    {
        var value = AsString(node);
        if (string.IsNullOrEmpty(value))
        {
            throw Refuse("INVALID_MANIFEST", $"{field} is required and must be a non-empty string");
        }
        if (value.Length > MaxTextLength)
        {
            throw Refuse("TEXT_OUT_OF_BOUNDS", $"{field} must not exceed {MaxTextLength} characters");
        }
        return value;
    }

    private static string? OptionalText(JsonNode? node, string field) =>
        node is null || (node is JsonValue leaf && leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.Null)
            ? null
            : Text(node, field);

    private static string KeyIdText(JsonNode? node, string field)
    {
        var value = Text(node, field);
        if (value.Any(character => character < 0x20 || character > 0x7e))
        {
            throw Refuse("INVALID_MANIFEST", $"{field} must be printable ASCII");
        }
        return value;
    }

    public static string? AsString(JsonNode? node) =>
        node is JsonValue leaf
            ? leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.String
                ? element.GetString()
                : leaf.TryGetValue<string>(out var text) ? text : null
            : null;

    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] DecodeBase64Url(JsonNode? node, string field, string code = "INVALID_SIGNATURE_ENCODING")
    {
        var value = AsString(node);
        return DecodeBase64Url(value, field, code);
    }

    public static byte[] DecodeBase64Url(string? value, string field, string code = "INVALID_SIGNATURE_ENCODING")
    {
        if (string.IsNullOrEmpty(value) || !Base64UrlPattern.IsMatch(value))
        {
            throw Refuse(code, $"{field} is not unpadded base64url");
        }
        byte[] data;
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            data = Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
        }
        catch (FormatException)
        {
            throw Refuse(code, $"{field} is not unpadded base64url");
        }
        if (Base64UrlEncode(data) != value)
        {
            throw Refuse(code, $"{field} is not a canonical unpadded base64url encoding");
        }
        return data;
    }

    public static string ComparableInstant(string? value, string field)
    {
        string canonical;
        try
        {
            canonical = Canonical.CanonicalTimestamp(value);
        }
        catch (CommitmentException error)
        {
            throw Refuse("INVALID_MANIFEST", $"{field}: {error.Message}");
        }
        var match = Regex.Match(canonical, "^(.+?)(?:\\.(\\d+))?Z$");
        return $"{match.Groups[1].Value}.{match.Groups[2].Value.PadRight(9, '0')}";
    }

    public static JsonObject RequirePublicJwk(JsonNode? node, string field)
    {
        if (node is not JsonObject jwk)
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field} must be a JSON Web Key object");
        }
        if (jwk.ContainsKey("d"))
        {
            throw Refuse("PRIVATE_KEY_MATERIAL", $"{field} carries a private component (d)");
        }
        var unknown = jwk.Select(pair => pair.Key).Where(member => !JwkMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field} carries {string.Join(", ", unknown)}");
        }
        var missing = JwkMembers.Where(member => !jwk.ContainsKey(member)).ToList();
        if (missing.Count > 0)
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field} is missing {string.Join(", ", missing)}");
        }
        if (AsString(jwk["kty"]) != "EC")
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field}.kty must be \"EC\"");
        }
        var curve = AsString(jwk["crv"]);
        var suite = Suites.Values.Cast<(string Curve, HashAlgorithmName Hash, int CoordinateLength, int SignatureLength)?>()
            .FirstOrDefault(candidate => candidate!.Value.Curve == curve);
        if (suite is null)
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field}.crv \"{curve}\" is not a curve this registry format defines");
        }
        foreach (var coordinate in new[] { "x", "y" })
        {
            var data = DecodeBase64Url(jwk[coordinate], $"{field}.{coordinate}", "INVALID_PUBLIC_KEY");
            if (data.Length != suite.Value.CoordinateLength)
            {
                throw Refuse("INVALID_PUBLIC_KEY", $"{field}.{coordinate} is {data.Length} bytes; curve {curve} requires exactly {suite.Value.CoordinateLength}, zero-padded (RFC 7518)");
            }
        }
        return jwk;
    }

    public static string JwkThumbprint(JsonNode? node)
    {
        var jwk = RequirePublicJwk(node, "publicKey");
        var canonical = Canonical.Canonicalize(new JsonObject
        {
            ["crv"] = AsString(jwk["crv"]),
            ["kty"] = AsString(jwk["kty"]),
            ["x"] = AsString(jwk["x"]),
            ["y"] = AsString(jwk["y"]),
        });
        return "sha256:" + Base64UrlEncode(SHA256.HashData(canonical));
    }

    public static void RequireSupported(string? formatVersion)
    {
        if (formatVersion != FormatVersion)
        {
            throw Refuse("UNKNOWN_REGISTRY_FORMAT_VERSION", $"Unknown trust-registry format version \"{formatVersion}\".");
        }
    }

    public static byte[] ManifestInput(JsonObject manifest)
    {
        RequireSupported(Canonical.StringOf(manifest, "formatVersion"));
        var header = string.Join(Separator, RegistryDomainTag, FormatVersion, "");
        return [.. Encoding.UTF8.GetBytes(header), .. Canonical.Canonicalize(manifest)];
    }

    public static string ManifestDigest(JsonObject manifest) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(ManifestInput(manifest))).ToLowerInvariant();

    public static string KeyStateAt(RegistryKey key, string instant)
    {
        var when = ComparableInstant(instant, "instant");
        if (key.RevokedAtUtc is not null && string.CompareOrdinal(when, ComparableInstant(key.RevokedAtUtc, "revokedAtUtc")) >= 0)
        {
            return "REVOKED";
        }
        if (key.RetiredAtUtc is not null && string.CompareOrdinal(when, ComparableInstant(key.RetiredAtUtc, "retiredAtUtc")) >= 0)
        {
            return "RETIRED";
        }
        if (string.CompareOrdinal(when, ComparableInstant(key.ValidFromUtc, "validFromUtc")) < 0)
        {
            return "NOT_YET_VALID";
        }
        return "ACTIVE";
    }

    private static void RequireExactMembers(JsonObject value, string[] expected, string field, string code = "INVALID_MANIFEST")
    {
        var declared = value.Select(pair => pair.Key).ToList();
        var unknown = declared.Where(member => !expected.Contains(member)).ToList();
        var missing = expected.Where(member => !declared.Contains(member)).ToList();
        if (unknown.Count > 0 || missing.Count > 0)
        {
            throw Refuse(code, $"{field} must declare exactly {string.Join(", ", expected)}"
                + (unknown.Count > 0 ? $"; unexpected: {string.Join(", ", unknown)}" : "")
                + (missing.Count > 0 ? $"; missing: {string.Join(", ", missing)}" : ""));
        }
    }

    public static long? IntegerOf(JsonNode? node)
    {
        if (node is JsonValue leaf && leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.Number)
        {
            // An integer VALUE, whatever its spelling — but a fractional value is not one.
            if (element.TryGetInt64(out var value))
            {
                return value;
            }
        }
        if (node is JsonValue direct && direct.TryGetValue<long>(out var plain))
        {
            return plain;
        }
        return null;
    }

    private static RegistryKey ValidateKey(JsonNode? node, string field, string issuedAtUtc)
    {
        if (node is not JsonObject raw)
        {
            throw Refuse("INVALID_MANIFEST", $"{field} must be an object");
        }
        RequireExactMembers(raw, KeyMembers, field);
        var key = new RegistryKey(
            KeyIdText(raw["keyId"], $"{field}.keyId"),
            raw["predecessorKeyId"] is null ? null : KeyIdText(raw["predecessorKeyId"], $"{field}.predecessorKeyId"),
            Text(raw["provider"], $"{field}.provider"),
            RequirePublicJwk(raw["publicKey"], $"{field}.publicKey"),
            OptionalText(raw["retiredAtUtc"], $"{field}.retiredAtUtc"),
            OptionalText(raw["revocationReason"], $"{field}.revocationReason"),
            OptionalText(raw["revokedAtUtc"], $"{field}.revokedAtUtc"),
            AsString(raw["status"]) ?? "",
            AsString(raw["suite"]) ?? "",
            Text(raw["thumbprint"], $"{field}.thumbprint"),
            AsString(raw["use"]) ?? "",
            Text(raw["validFromUtc"], $"{field}.validFromUtc"));

        if (!KeyUses.Contains(key.Use))
        {
            throw Refuse("UNKNOWN_KEY_USE", $"{field}.use must be one of {string.Join(", ", KeyUses)}");
        }
        if (!Suites.ContainsKey(key.Suite))
        {
            throw Refuse("UNKNOWN_SUITE", $"{field}.suite must be one of {string.Join(", ", Suites.Keys)}");
        }
        if (Suites[key.Suite].Curve != AsString(key.PublicKey["crv"]))
        {
            throw Refuse("INVALID_PUBLIC_KEY", $"{field}: suite {key.Suite} signs on another curve than the key");
        }
        if (!KeyStatuses.Contains(key.Status))
        {
            throw Refuse("INVALID_MANIFEST", $"{field}.status must be one of {string.Join(", ", KeyStatuses)}");
        }
        var computed = JwkThumbprint(key.PublicKey);
        if (computed != key.Thumbprint)
        {
            throw Refuse("THUMBPRINT_MISMATCH", $"{field}.thumbprint is {key.Thumbprint} but the key thumbprints to {computed}");
        }
        if (key.RevocationReason is not null && key.RevokedAtUtc is null)
        {
            throw Refuse("INVALID_MANIFEST", $"{field}.revocationReason is set on a key that is not revoked");
        }
        if (string.CompareOrdinal(ComparableInstant(key.ValidFromUtc, $"{field}.validFromUtc"), ComparableInstant(issuedAtUtc, "manifest.issuedAtUtc")) > 0)
        {
            throw Refuse("KEY_NOT_YET_VALID", $"{field}.validFromUtc is after the manifest's own issuedAtUtc");
        }
        var stateAtIssue = KeyStateAt(key, issuedAtUtc);
        if (stateAtIssue != key.Status)
        {
            throw Refuse("KEY_STATUS_INCONSISTENT", $"{field}.status is {key.Status}, but its own timestamps put it at {stateAtIssue}");
        }
        return key;
    }

    public static (JsonNode? Attestations, ValidatedManifest Manifest, List<ManifestSignature> Signatures) ValidateRegistryDocument(JsonNode? node)
    {
        if (node is not JsonObject document)
        {
            throw Refuse("INVALID_MANIFEST", "A trust-registry document must be an object");
        }
        RequireExactMembers(document, ["attestations", "manifest", "signatures"], "The document");
        if (document["manifest"] is not JsonObject raw)
        {
            throw Refuse("INVALID_MANIFEST", "document.manifest must be an object");
        }
        RequireExactMembers(raw, ManifestMembers, "manifest");
        RequireSupported(AsString(raw["formatVersion"]));

        var registryVersion = IntegerOf(raw["registryVersion"]);
        if (registryVersion is null || registryVersion < 1 || !IsIntegerSpelling(raw["registryVersion"]))
        {
            throw Refuse("INVALID_MANIFEST", "manifest.registryVersion must be an integer of at least 1");
        }
        var issuedAtUtc = Text(raw["issuedAtUtc"], "manifest.issuedAtUtc");
        ComparableInstant(issuedAtUtc, "manifest.issuedAtUtc");

        var previousIsNull = raw["previous"] is null;
        if ((registryVersion == 1) != previousIsNull)
        {
            throw Refuse("REGISTRY_CHAIN_BROKEN", registryVersion == 1
                ? "The first manifest has no predecessor, so manifest.previous must be null"
                : "Only the first manifest may have a null manifest.previous");
        }
        JsonObject? previous = null;
        if (!previousIsNull)
        {
            if (raw["previous"] is not JsonObject previousObject)
            {
                throw Refuse("INVALID_MANIFEST", "manifest.previous must be an object or null");
            }
            RequireExactMembers(previousObject, ["digest", "registryVersion"], "manifest.previous");
            previous = previousObject;
            var previousVersion = IntegerOf(previousObject["registryVersion"]);
            var digest = Text(previousObject["digest"], "manifest.previous.digest");
            if (previousVersion is null || previousVersion != registryVersion - 1)
            {
                throw Refuse("REGISTRY_CHAIN_BROKEN", $"manifest.previous.registryVersion must be {registryVersion - 1}");
            }
            if (!DigestPattern.IsMatch(digest))
            {
                throw Refuse("INVALID_MANIFEST", "manifest.previous.digest must be \"sha256:\" and 64 lowercase hex");
            }
        }

        if (raw["keys"] is not JsonArray keysArray || keysArray.Count == 0)
        {
            throw Refuse("INVALID_MANIFEST", "manifest.keys must be a non-empty array");
        }
        var keys = keysArray.Select((key, index) => ValidateKey(key, $"manifest.keys[{index}]", issuedAtUtc)).ToList();

        var manifest = new ValidatedManifest(
            AsString(raw["formatVersion"])!, issuedAtUtc, Text(raw["issuer"], "manifest.issuer"),
            keys, previous, registryVersion.Value, raw);

        var ids = new HashSet<string>();
        foreach (var key in keys)
        {
            if (!ids.Add(key.KeyId))
            {
                throw Refuse("DUPLICATE_KEY_ID", $"manifest.keys declares \"{key.KeyId}\" more than once");
            }
        }
        foreach (var key in keys)
        {
            if (key.PredecessorKeyId is not null && !ids.Contains(key.PredecessorKeyId))
            {
                throw Refuse("INVALID_MANIFEST", $"\"{key.KeyId}\" names an undeclared predecessor");
            }
        }

        if (document["signatures"] is not JsonArray signaturesArray || signaturesArray.Count == 0)
        {
            throw Refuse("INVALID_MANIFEST", "document.signatures must be a non-empty array");
        }
        var signatures = new List<ManifestSignature>();
        for (var index = 0; index < signaturesArray.Count; index += 1)
        {
            var field = $"signatures[{index}]";
            if (signaturesArray[index] is not JsonObject entry)
            {
                throw Refuse("INVALID_MANIFEST", $"{field} must be an object");
            }
            RequireExactMembers(entry, ["keyId", "signature", "suite"], field);
            var keyId = KeyIdText(entry["keyId"], $"{field}.keyId");
            var signer = keys.FirstOrDefault(key => key.KeyId == keyId)
                ?? throw Refuse("UNKNOWN_SIGNER", $"{field} names key \"{keyId}\", which the manifest it signs does not declare");
            if (signer.Use != "trust-root")
            {
                throw Refuse("UNKNOWN_SIGNER", $"{field} is made by \"{keyId}\", whose use is {signer.Use}");
            }
            var suite = AsString(entry["suite"]);
            if (suite != signer.Suite)
            {
                throw Refuse("INVALID_MANIFEST", $"{field}.suite is {suite} but the key is declared as {signer.Suite}");
            }
            var signature = DecodeBase64Url(entry["signature"], $"{field}.signature");
            if (signature.Length != Suites[signer.Suite].SignatureLength)
            {
                throw Refuse("MALFORMED_SIGNATURE", $"{field}.signature is {signature.Length} bytes");
            }
            signatures.Add(new ManifestSignature(keyId, signature, signer, suite!));
        }
        var signerIds = new HashSet<string>();
        foreach (var entry in signatures)
        {
            if (!signerIds.Add(entry.KeyId))
            {
                throw Refuse("INVALID_MANIFEST", $"document.signatures names \"{entry.KeyId}\" more than once");
            }
        }
        var attestations = document["attestations"];
        if (attestations is not null && attestations is not JsonObject)
        {
            throw Refuse("INVALID_MANIFEST", "document.attestations must be an object or null");
        }
        return (attestations, manifest, signatures);
    }

    /// <summary>Whether a JSON number was an integer VALUE (no fractional part after judging).</summary>
    private static bool IsIntegerSpelling(JsonNode? node) =>
        node is JsonValue leaf && leaf.TryGetValue<JsonElement>(out var element)
            ? element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out _)
            : node is JsonValue direct && direct.TryGetValue<long>(out _);

    public static ECDsa LoadPublicKey(JsonObject jwk, string suite)
    {
        var parameters = new ECParameters
        {
            Curve = Suites[suite].Curve == "P-256" ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384,
            Q = new ECPoint
            {
                X = DecodeBase64Url(jwk["x"], "jwk.x", "INVALID_PUBLIC_KEY"),
                Y = DecodeBase64Url(jwk["y"], "jwk.y", "INVALID_PUBLIC_KEY"),
            },
        };
        var key = ECDsa.Create();
        key.ImportParameters(parameters); // throws for a point off the curve
        return key;
    }

    public static bool SignatureVerifies(byte[] data, JsonObject jwk, string suite, byte[] signature)
    {
        try
        {
            using var key = LoadPublicKey(jwk, suite);
            return key.VerifyData(data, signature, Suites[suite].Hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception exception) when (exception is CryptographicException or TrustRegistryException or ArgumentException)
        {
            return false;
        }
    }

    private static void RequirePin(JsonObject? pin)
    {
        if (pin is null || AsString(pin["issuer"]) is null || AsString(pin["root"]) is null)
        {
            throw Refuse("NO_TRUST_ANCHOR", "A pinned root { issuer, root } is required; there is no pinless mode");
        }
    }

    public static VerifiedManifest VerifyManifest(JsonNode? document, JsonObject pin)
    {
        RequirePin(pin);
        var (attestations, manifest, signatures) = ValidateRegistryDocument(document);
        if (manifest.Issuer != AsString(pin["issuer"]))
        {
            throw Refuse("ISSUER_MISMATCH", $"The manifest is issued by \"{manifest.Issuer}\", but the pin names \"{AsString(pin["issuer"])}\"");
        }
        var pinned = signatures.FirstOrDefault(entry => entry.Signer.Thumbprint == AsString(pin["root"]))
            ?? throw Refuse("ROOT_MISMATCH", "No signature on this manifest was made by the pinned root");
        if (!SignatureVerifies(ManifestInput(manifest.Raw), pinned.Signer.PublicKey, pinned.Suite, pinned.Signature))
        {
            throw Refuse("REGISTRY_SIGNATURE_INVALID", "The pinned root's signature does not verify over this manifest");
        }
        return new VerifiedManifest(attestations, ManifestDigest(manifest.Raw), manifest, pinned.Signer.KeyId, pinned.Signer.Status);
    }

    public sealed record ChainOutcome(VerifiedManifest Accepted, List<string> ReasonCodes, JsonObject State);

    public static ChainOutcome AcceptChain(JsonArray documents, JsonObject pin, JsonObject? state)
    {
        RequirePin(pin);
        if (documents.Count == 0)
        {
            throw Refuse("INVALID_MANIFEST", "acceptChain requires at least one trust-registry document");
        }
        if (state is not null)
        {
            if (AsString(state["issuer"]) is null || AsString(state["root"]) is null)
            {
                throw Refuse("NO_TRUST_ANCHOR", "The verifier state must record the { issuer, root } it was established under");
            }
            if (AsString(state["issuer"]) != AsString(pin["issuer"]))
            {
                throw Refuse("ISSUER_MISMATCH", "The verifier state was established for another issuer");
            }
            if (AsString(state["root"]) != AsString(pin["root"]))
            {
                throw Refuse("ROOT_MISMATCH", "The verifier state was established under a different trust root");
            }
        }

        JsonObject? current = state is null ? null : (JsonObject)state.DeepClone();
        VerifiedManifest? accepted = null;
        foreach (var documentNode in documents)
        {
            var verified = VerifyManifest(documentNode, pin);
            var manifestVersion = verified.Manifest.RegistryVersion;
            if (current is not null)
            {
                var currentVersion = Registry.IntegerOf(current["registryVersion"])!.Value;
                if (manifestVersion < currentVersion)
                {
                    // History below the held watermark: verified, never current.
                    continue;
                }
                if (manifestVersion == currentVersion)
                {
                    if (verified.Digest != AsString(current["digest"]))
                    {
                        throw Refuse("REGISTRY_FORK", $"Two different manifests both claim registry version {manifestVersion}");
                    }
                    accepted = verified;
                    continue;
                }
                if (manifestVersion != currentVersion + 1)
                {
                    throw Refuse("REGISTRY_CHAIN_BROKEN", $"Cannot step from registry version {currentVersion} to {manifestVersion}");
                }
                var previous = verified.Manifest.Previous!;
                if (Registry.IntegerOf(previous["registryVersion"]) != currentVersion || AsString(previous["digest"]) != AsString(current["digest"]))
                {
                    throw Refuse("REGISTRY_CHAIN_BROKEN", $"Registry version {manifestVersion} does not link to the held manifest");
                }
            }
            current = new JsonObject
            {
                ["digest"] = verified.Digest,
                ["issuer"] = verified.Manifest.Issuer,
                ["registryVersion"] = verified.Manifest.RegistryVersion,
                ["root"] = AsString(pin["root"]),
            };
            accepted = verified;
        }
        if (accepted is null)
        {
            throw Refuse("REGISTRY_ROLLBACK",
                $"Every served manifest is older than registry version {Registry.IntegerOf(current!["registryVersion"])}, which this verifier has already accepted");
        }
        var reasonCodes = new List<string>();
        if (accepted.RootStatus == "REVOKED")
        {
            reasonCodes.Add("ROOT_REVOKED");
        }
        else if (accepted.RootStatus == "RETIRED")
        {
            reasonCodes.Add("ROOT_RETIRED");
        }
        return new ChainOutcome(accepted, reasonCodes, current!);
    }

    public static (RegistryKey? Key, string? Reason) ResolveSigningKey(ValidatedManifest manifest, string? keyId)
    {
        var key = manifest.Keys.FirstOrDefault(candidate => candidate.KeyId == keyId);
        if (key is null)
        {
            return (null, "UNKNOWN_KEY");
        }
        if (key.Use != "evidence-signing")
        {
            return (key, "KEY_USE_MISMATCH");
        }
        return (key, null);
    }

    public static byte[] SealSigningInput(JsonObject envelope)
    {
        var version = Canonical.StringOf(envelope, "version");
        if (version != SealEnvelopeVersion)
        {
            throw Refuse("UNKNOWN_ENVELOPE_VERSION", $"Unknown evidence-envelope version \"{version}\".");
        }
        var header = string.Join(Separator, SealDomainTag, version, "");
        return [.. Encoding.UTF8.GetBytes(header), .. Canonical.Canonicalize(envelope)];
    }

    public static SealVerdict VerifySeal(
        JsonObject seal, ValidatedManifest manifest, JsonObject expectedSubject,
        string? expectedCommitmentDigest, IEnumerable<string> registryReasonCodes)
    {
        if (seal["envelope"] is not JsonObject envelope)
        {
            throw Refuse("INVALID_MANIFEST", "seal must be { envelope, signature }");
        }
        var dimensions = new Dictionary<string, string>
        {
            ["content"] = "NOT_CHECKED",
            ["keyIdentity"] = "NOT_CHECKED",
            ["keyLifecycle"] = "NOT_CHECKED",
            ["signature"] = "NOT_CHECKED",
            ["subject"] = "NOT_CHECKED",
        };
        var reasonCodes = registryReasonCodes.ToList();
        SealVerdict Invalid(string code)
        {
            reasonCodes.Add(code);
            return new SealVerdict(dimensions, reasonCodes, "INVALID");
        }

        if (Canonical.StringOf(envelope, "version") != SealEnvelopeVersion)
        {
            return Invalid("UNKNOWN_ENVELOPE_VERSION");
        }
        if (envelope["signer"] is not JsonObject signerRef || Canonical.StringOf(signerRef, "keyId") is null)
        {
            return Invalid("MALFORMED_ENVELOPE");
        }
        var (key, reason) = ResolveSigningKey(manifest, Canonical.StringOf(signerRef, "keyId"));
        if (reason is not null)
        {
            return Invalid(reason);
        }
        dimensions["keyIdentity"] = "TRUSTED";
        if (Canonical.StringOf(signerRef, "suite") != key!.Suite)
        {
            return Invalid("KEY_SUITE_MISMATCH");
        }
        if (Canonical.StringOf(signerRef, "provider") != key.Provider)
        {
            return Invalid("KEY_PROVIDER_MISMATCH");
        }

        byte[] signature;
        try
        {
            signature = DecodeBase64Url(seal["signature"], "seal.signature");
        }
        catch (TrustRegistryException)
        {
            return Invalid("MALFORMED_SIGNATURE");
        }
        if (signature.Length != Suites[key.Suite].SignatureLength)
        {
            return Invalid("MALFORMED_SIGNATURE");
        }

        byte[] signingInput;
        try
        {
            signingInput = SealSigningInput(envelope);
        }
        catch (Exception exception) when (exception is TrustRegistryException or CommitmentException)
        {
            return Invalid("MALFORMED_ENVELOPE");
        }

        if (!SignatureVerifies(signingInput, key.PublicKey, key.Suite, signature))
        {
            dimensions["signature"] = "INVALID";
            return Invalid("SIGNATURE_INVALID");
        }
        dimensions["signature"] = "VALID";

        var committedAt = Canonical.StringOf(envelope, "committedAt");
        if (committedAt is null)
        {
            return Invalid("MALFORMED_ENVELOPE");
        }
        string stateWhenSigned;
        try
        {
            stateWhenSigned = KeyStateAt(key, committedAt);
        }
        catch (TrustRegistryException)
        {
            return Invalid("MALFORMED_ENVELOPE");
        }
        dimensions["keyLifecycle"] = stateWhenSigned;
        if (stateWhenSigned == "NOT_YET_VALID")
        {
            return Invalid("SIGNED_BEFORE_KEY_VALID");
        }
        if (stateWhenSigned == "REVOKED")
        {
            return Invalid("SIGNED_AFTER_REVOCATION");
        }
        if (stateWhenSigned == "RETIRED")
        {
            return Invalid("SIGNED_AFTER_RETIREMENT");
        }

        var weakened = reasonCodes.Contains("ROOT_REVOKED");
        if (key.RevokedAtUtc is not null)
        {
            reasonCodes.Add("SIGNED_BEFORE_REVOCATION");
            reasonCodes.Add("COMMITTED_AT_SELF_ASSERTED");
            weakened = true;
        }
        else if (key.RetiredAtUtc is not null)
        {
            reasonCodes.Add("KEY_RETIRED_AFTER_SIGNING");
        }

        var subject = envelope["subject"] as JsonObject;
        if (subject is null
            || Canonical.StringOf(subject, "tenantId") != Canonical.StringOf(expectedSubject, "tenantId")
            || Canonical.StringOf(subject, "actionId") != Canonical.StringOf(expectedSubject, "actionId")
            || Canonical.StringOf(subject, "evidenceId") != Canonical.StringOf(expectedSubject, "evidenceId")
            || IntegerOf(subject["sequence"]) != IntegerOf(expectedSubject["sequence"]))
        {
            dimensions["subject"] = "MISMATCH";
            return Invalid("SUBJECT_MISMATCH");
        }
        dimensions["subject"] = "MATCHES";

        if (expectedCommitmentDigest is null)
        {
            reasonCodes.Add("COMMITMENT_NOT_CHECKED");
            weakened = true;
        }
        else if (envelope["commitment"] is not JsonObject commitment || Canonical.StringOf(commitment, "digest") != expectedCommitmentDigest)
        {
            dimensions["content"] = "MISMATCH";
            return Invalid("COMMITMENT_MISMATCH");
        }
        else
        {
            dimensions["content"] = "MATCHES";
        }

        return new SealVerdict(dimensions, reasonCodes, weakened ? "PARTIAL" : "VALID");
    }
}
