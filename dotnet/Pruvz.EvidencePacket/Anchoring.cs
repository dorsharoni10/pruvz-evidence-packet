// External anchoring, format version 1 — independent .NET implementation
// (PRUVZ-97), from docs/ANCHORING.md. Half one (the binding) is the
// Pruvz-specific composition; the RFC 3161 token is read with the platform's
// System.Formats.Asn1 reader, and half two lives in Authority.cs.

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Pruvz.EvidencePacket;

public sealed class AnchorException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record TimestampTokenInfo(string PolicyOid, string AlgorithmOid, string? Algorithm, byte[] Hash, byte[]? Nonce, string GenTime);

public static class Anchoring
{
    public const string FormatVersion = "1";
    public static readonly Dictionary<string, string> SubjectDomainTags = new()
    {
        ["log-checkpoint"] = "pruvz.ai/log-anchor",
        ["trust-registry"] = "pruvz.ai/trust-registry-anchor",
    };
    private const char Separator = '\u0000';
    public const int BlindingNonceBytes = 32;
    public const int MinRequestNonceBytes = 8;
    public static readonly string[] AnchorStatuses = ["ANCHORED", "PENDING", "FAILED"];
    public const string ReceiptKind = "rfc3161-timestamp-token";
    private const int MaxBoundTextLength = 512;
    private const long MaxSafeInteger = 9007199254740991;

    private const string OidSignedData = "1.2.840.113549.1.7.2";
    private const string OidTstInfo = "1.2.840.113549.1.9.16.1.4";
    private const string OidSha256 = "2.16.840.1.101.3.4.2.1";

    private static readonly Regex PrintableAscii = new("^[\\x20-\\x7e]+$", RegexOptions.Compiled);
    private static readonly Regex Base64UrlPattern = new("^[A-Za-z0-9_-]+$", RegexOptions.Compiled);
    private static readonly Regex Base64Pattern = new("^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled);

    private static AnchorException Refuse(string code, string message) => new(code, message);

    private static string BoundText(JsonNode? node, string field)
    {
        var value = Registry.AsString(node);
        if (string.IsNullOrEmpty(value))
        {
            throw Refuse("ANCHOR_MALFORMED", $"{field} is required");
        }
        if (value.Length > MaxBoundTextLength || !PrintableAscii.IsMatch(value))
        {
            throw Refuse("ANCHOR_MALFORMED", $"{field} is out of bounds or not printable ASCII");
        }
        return value;
    }

    public static byte[] DecodeBase64Url(JsonNode? node, string field)
    {
        var value = Registry.AsString(node);
        if (string.IsNullOrEmpty(value) || !Base64UrlPattern.IsMatch(value))
        {
            throw Refuse("ANCHOR_MALFORMED", $"{field} must be unpadded base64url");
        }
        byte[] data;
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            data = Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
        }
        catch (FormatException)
        {
            throw Refuse("ANCHOR_MALFORMED", $"{field} must be unpadded base64url");
        }
        if (Registry.Base64UrlEncode(data) != value)
        {
            throw Refuse("ANCHOR_MALFORMED", $"{field} is not a canonical unpadded base64url encoding");
        }
        return data;
    }

    public static byte[] DecodeBase64(string? value, string field)
    {
        if (string.IsNullOrEmpty(value) || !Base64Pattern.IsMatch(value))
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"{field} must be base64");
        }
        byte[] data;
        try
        {
            data = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"{field} must be base64");
        }
        if (Convert.ToBase64String(data) != value)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"{field} is not a canonical base64 encoding");
        }
        return data;
    }

    public static byte[] Unsigned(byte[] data)
    {
        var start = 0;
        while (start < data.Length - 1 && data[start] == 0)
        {
            start += 1;
        }
        return data[start..];
    }

    public static void RequireSupported(string? formatVersion)
    {
        if (formatVersion != FormatVersion)
        {
            throw Refuse("UNKNOWN_ANCHOR_VERSION", $"Unknown anchoring version \"{formatVersion}\".");
        }
    }

    // -- Subjects ------------------------------------------------------------

    public sealed record SubjectMaterialInfo(JsonObject Document, string Origin, long SubjectVersion);

    public static SubjectMaterialInfo SubjectMaterial(string? kind, JsonNode? subjectNode)
    {
        if (kind is null || !SubjectDomainTags.ContainsKey(kind))
        {
            throw Refuse("ANCHOR_MALFORMED", $"subject.kind \"{kind}\" is not a subject this format anchors");
        }
        if (subjectNode is not JsonObject subject)
        {
            throw Refuse("ANCHOR_MALFORMED", "a subject must be an object");
        }
        if (kind == "log-checkpoint")
        {
            var unknown = subject.Select(pair => pair.Key).Where(member => member != "checkpoint" && member != "signature").ToList();
            if (unknown.Count > 0)
            {
                throw Refuse("ANCHOR_MALFORMED", $"a log-checkpoint subject holds exactly checkpoint and signature; got {string.Join(", ", unknown)}");
            }
            if (subject["checkpoint"] is not JsonObject checkpoint)
            {
                throw Refuse("ANCHOR_MALFORMED", "a log-checkpoint subject must carry a checkpoint object");
            }
            try
            {
                EvidenceLog.ValidateCheckpointDocument(checkpoint);
            }
            catch (EvidenceLogException error)
            {
                throw Refuse("ANCHOR_MALFORMED", $"the checkpoint being anchored is not valid: {error.Message}");
            }
            DecodeBase64Url(subject["signature"], "subject.signature");
            return new SubjectMaterialInfo(
                new JsonObject { ["checkpoint"] = checkpoint.DeepClone(), ["signature"] = subject["signature"]!.DeepClone() },
                Canonical.StringOf(checkpoint, "origin")!,
                Registry.IntegerOf(checkpoint["checkpointSequence"])!.Value);
        }
        if (subject["manifest"] is not JsonObject manifest)
        {
            throw Refuse("ANCHOR_MALFORMED", "a trust-registry subject must carry a manifest object");
        }
        if (subject["signatures"] is not JsonArray signatures || signatures.Count == 0)
        {
            throw Refuse("ANCHOR_MALFORMED", "a trust-registry subject must carry a non-empty signatures array");
        }
        var issuer = BoundText(manifest["issuer"], "subject.manifest.issuer");
        var registryVersion = Registry.IntegerOf(manifest["registryVersion"]);
        if (registryVersion is null || registryVersion < 1)
        {
            throw Refuse("ANCHOR_MALFORMED", "subject.manifest.registryVersion must be a positive integer");
        }
        return new SubjectMaterialInfo(
            new JsonObject { ["manifest"] = manifest.DeepClone(), ["signatures"] = signatures.DeepClone() },
            issuer,
            registryVersion.Value);
    }

    public static byte[] AnchorInput(string kind, byte[] blindingNonce, JsonNode? subject)
    {
        var material = SubjectMaterial(kind, subject);
        if (blindingNonce.Length != BlindingNonceBytes)
        {
            throw Refuse("ANCHOR_MALFORMED", $"a blinding nonce is exactly {BlindingNonceBytes} bytes; got {blindingNonce.Length}");
        }
        var header = string.Join(Separator, SubjectDomainTags[kind], FormatVersion, "");
        byte[] body;
        try
        {
            body = Canonical.Canonicalize(material.Document);
        }
        catch (CommitmentException error)
        {
            throw Refuse("ANCHOR_MALFORMED", $"a subject cannot be canonicalized: {error.Message}");
        }
        return [.. Encoding.UTF8.GetBytes(header), .. blindingNonce, .. body];
    }

    public static byte[] AnchorImprint(string kind, byte[] blindingNonce, JsonNode? subject) =>
        SHA256.HashData(AnchorInput(kind, blindingNonce, subject));

    // -- The anchor record ---------------------------------------------------

    private static readonly string[] RecordMembers =
    [
        "anchorId", "blindingNonce", "receipt", "requestNonce", "status", "subject", "trustDomain", "version",
    ];
    private static readonly string[] SubjectMembers = ["kind", "origin", "subjectVersion"];
    private static readonly string[] ReceiptMembers = ["kind", "token"];

    public static (byte[] BlindingNonce, byte[] RequestNonce) ValidateAnchorRecord(JsonNode? node)
    {
        if (node is not JsonObject record)
        {
            throw Refuse("ANCHOR_MALFORMED", "an anchor record must be an object");
        }
        RequireSupported(Canonical.StringOf(record, "version"));
        var unknown = record.Select(pair => pair.Key).Where(member => !RecordMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("ANCHOR_MALFORMED", $"an anchor record carries {string.Join(", ", unknown)}; the member set is closed");
        }
        var missing = RecordMembers.Where(member => !record.ContainsKey(member)).ToList();
        if (missing.Count > 0)
        {
            throw Refuse("ANCHOR_MALFORMED", $"an anchor record is missing {string.Join(", ", missing)}");
        }
        BoundText(record["anchorId"], "anchorId");
        BoundText(record["trustDomain"], "trustDomain");
        var status = Canonical.StringOf(record, "status");
        if (status is null || !AnchorStatuses.Contains(status))
        {
            throw Refuse("ANCHOR_MALFORMED", $"status must be one of {string.Join(", ", AnchorStatuses)}");
        }
        if (record["subject"] is not JsonObject subject)
        {
            throw Refuse("ANCHOR_MALFORMED", "subject must be an object");
        }
        var subjectUnknown = subject.Select(pair => pair.Key).Where(member => !SubjectMembers.Contains(member)).ToList();
        if (subjectUnknown.Count > 0)
        {
            throw Refuse("ANCHOR_MALFORMED", $"subject carries {string.Join(", ", subjectUnknown)}; it holds exactly {string.Join(", ", SubjectMembers)}");
        }
        var kind = Canonical.StringOf(subject, "kind");
        if (kind is null || !SubjectDomainTags.ContainsKey(kind))
        {
            throw Refuse("ANCHOR_MALFORMED", $"subject.kind must be one of {string.Join(", ", SubjectDomainTags.Keys)}");
        }
        BoundText(subject["origin"], "subject.origin");
        var subjectVersion = Registry.IntegerOf(subject["subjectVersion"]);
        if (subjectVersion is null || subjectVersion < 1 || subjectVersion > MaxSafeInteger)
        {
            throw Refuse("ANCHOR_MALFORMED", "subject.subjectVersion must be a positive integer");
        }

        var blindingNonce = DecodeBase64Url(record["blindingNonce"], "blindingNonce");
        if (blindingNonce.Length != BlindingNonceBytes)
        {
            throw Refuse("ANCHOR_MALFORMED", $"blindingNonce is {blindingNonce.Length} bytes; it is exactly {BlindingNonceBytes}");
        }
        var requestNonce = DecodeBase64Url(record["requestNonce"], "requestNonce");
        if (requestNonce.Length < MinRequestNonceBytes)
        {
            throw Refuse("ANCHOR_MALFORMED", $"requestNonce is {requestNonce.Length} bytes; at least {MinRequestNonceBytes} are required");
        }

        if (status == "ANCHORED")
        {
            if (record["receipt"] is not JsonObject receipt)
            {
                throw Refuse("ANCHOR_MALFORMED", "an ANCHORED record must carry a receipt");
            }
            var receiptUnknown = receipt.Select(pair => pair.Key).Where(member => !ReceiptMembers.Contains(member)).ToList();
            if (receiptUnknown.Count > 0)
            {
                throw Refuse("ANCHOR_MALFORMED", $"receipt carries {string.Join(", ", receiptUnknown)}; it holds exactly kind, token");
            }
            if (Canonical.StringOf(receipt, "kind") != ReceiptKind)
            {
                throw Refuse("ANCHOR_MALFORMED", $"receipt.kind must be \"{ReceiptKind}\"");
            }
            if (string.IsNullOrEmpty(Canonical.StringOf(receipt, "token")))
            {
                throw Refuse("ANCHOR_MALFORMED", "receipt.token is required");
            }
        }
        else if (record["receipt"] is not null)
        {
            throw Refuse("ANCHOR_MALFORMED", $"a {status} record must carry receipt: null");
        }
        return (blindingNonce, requestNonce);
    }

    // -- Reading an RFC 3161 TimeStampToken ----------------------------------

    public static TimestampTokenInfo ReadTimestampToken(byte[] der)
    {
        try
        {
            var reader = new AsnReader(der, AsnEncodingRules.DER);
            var contentInfo = reader.ReadSequence();
            reader.ThrowIfNotEmpty();
            var contentType = contentInfo.ReadObjectIdentifier();
            if (contentType != OidSignedData)
            {
                throw Refuse("ANCHOR_RECEIPT_MALFORMED", "the token is not a CMS SignedData");
            }
            var explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var signedData = explicitContent.ReadSequence();
            signedData.ReadInteger(); // version
            signedData.ReadSetOf(); // digestAlgorithms
            var encap = signedData.ReadSequence();
            var eContentType = encap.ReadObjectIdentifier();
            if (eContentType != OidTstInfo)
            {
                throw Refuse("ANCHOR_RECEIPT_MALFORMED", "the encapsulated content is not a TSTInfo");
            }
            var eContent = encap.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var tstDer = eContent.ReadOctetString();
            var tst = new AsnReader(tstDer, AsnEncodingRules.DER).ReadSequence();
            tst.ReadInteger(); // version
            var policyOid = tst.ReadObjectIdentifier();
            var messageImprint = tst.ReadSequence();
            var algorithmIdentifier = messageImprint.ReadSequence();
            var algorithmOid = algorithmIdentifier.ReadObjectIdentifier();
            if (algorithmIdentifier.HasData)
            {
                algorithmIdentifier.ReadNull();
                algorithmIdentifier.ThrowIfNotEmpty();
            }
            var hashedMessage = messageImprint.ReadOctetString();
            messageImprint.ThrowIfNotEmpty();
            tst.ReadInteger(); // serialNumber
            var genTimeValue = tst.ReadGeneralizedTime();

            byte[]? nonce = null;
            while (tst.HasData)
            {
                var tag = tst.PeekTag();
                if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Integer)
                {
                    nonce = Unsigned(tst.ReadIntegerBytes().ToArray());
                }
                else if (
                    (tag.TagClass == TagClass.Universal && (tag.TagValue == (int)UniversalTagNumber.Sequence || tag.TagValue == (int)UniversalTagNumber.Boolean))
                    || (tag.TagClass == TagClass.ContextSpecific && (tag.TagValue == 0 || tag.TagValue == 1)))
                {
                    tst.ReadEncodedValue();
                }
                else
                {
                    throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"an unexpected TSTInfo member (tag {tag})");
                }
            }

            var utc = genTimeValue.UtcDateTime;
            var ticksFraction = (genTimeValue.Ticks % TimeSpan.TicksPerSecond).ToString("D7").TrimEnd('0');
            var genTimeIso = utc.ToString("yyyy-MM-dd'T'HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture)
                + (ticksFraction.Length > 0 ? "." + ticksFraction : "") + "Z";
            var genTime = Canonical.CanonicalTimestamp(genTimeIso);
            return new TimestampTokenInfo(
                policyOid,
                algorithmOid,
                algorithmOid == OidSha256 ? "sha-256" : null,
                hashedMessage,
                nonce,
                genTime);
        }
        catch (AnchorException)
        {
            throw;
        }
        catch (Exception error) when (error is AsnContentException or InvalidOperationException or ArgumentException or CommitmentException)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"receipt.token cannot be fully read: {error.Message}");
        }
    }

    private static string ReadGeneralizedTime(string text)
    {
        var match = Regex.Match(text, "^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(?:\\.(\\d+))?Z$");
        if (!match.Success)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"genTime \"{text}\" is not a UTC GeneralizedTime");
        }
        var iso = $"{match.Groups[1].Value}-{match.Groups[2].Value}-{match.Groups[3].Value}T{match.Groups[4].Value}:{match.Groups[5].Value}:{match.Groups[6].Value}"
            + (match.Groups[7].Success ? $".{match.Groups[7].Value}" : "") + "Z";
        return Canonical.CanonicalTimestamp(iso);
    }

    // -- Verification — half one ---------------------------------------------

    public sealed record BindingResult(JsonObject Subject, string TrustDomain, string AnchorId, string Imprint, string GenTime, string PolicyOid);

    public static BindingResult VerifyAnchorBinding(JsonObject record, JsonNode? subject)
    {
        var (blindingNonce, requestNonce) = ValidateAnchorRecord(record);
        if (Canonical.StringOf(record, "status") != "ANCHORED")
        {
            throw Refuse("ANCHOR_NOT_PRESENT", $"this anchor is {Canonical.StringOf(record, "status")}");
        }
        var recordSubject = (JsonObject)record["subject"]!;
        var kind = Canonical.StringOf(recordSubject, "kind")!;
        var material = SubjectMaterial(kind, subject);
        if (material.Origin != Canonical.StringOf(recordSubject, "origin"))
        {
            throw Refuse("ANCHOR_MALFORMED", $"this record names origin \"{Canonical.StringOf(recordSubject, "origin")}\"; the subject is from \"{material.Origin}\"");
        }
        if (material.SubjectVersion != Registry.IntegerOf(recordSubject["subjectVersion"]))
        {
            throw Refuse("ANCHOR_MALFORMED", "this record names a different subject version");
        }
        var imprint = AnchorImprint(kind, blindingNonce, subject);
        var receipt = (JsonObject)record["receipt"]!;
        var token = ReadTimestampToken(DecodeBase64(Canonical.StringOf(receipt, "token"), "receipt.token"));
        if (token.Algorithm is null)
        {
            throw Refuse("ANCHOR_SUITE_UNSUPPORTED", $"the token's messageImprint uses {token.AlgorithmOid}, which this format does not define");
        }
        if (!token.Hash.AsSpan().SequenceEqual(imprint))
        {
            throw Refuse("ANCHOR_BINDING_MISMATCH", "the token witnesses a different imprint than this subject and blinding nonce produce");
        }
        if (token.Nonce is null)
        {
            throw Refuse("ANCHOR_NONCE_MISMATCH", "the token carries no nonce; this record names one");
        }
        if (!token.Nonce.AsSpan().SequenceEqual(Unsigned(requestNonce)))
        {
            throw Refuse("ANCHOR_NONCE_MISMATCH", "the token answers a different request than this record names");
        }
        return new BindingResult(
            recordSubject,
            Canonical.StringOf(record, "trustDomain")!,
            Canonical.StringOf(record, "anchorId")!,
            Convert.ToHexString(imprint).ToLowerInvariant(),
            token.GenTime,
            token.PolicyOid);
    }
}
