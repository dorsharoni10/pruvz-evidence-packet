// Half two of anchor verification (docs/ANCHORING.md §6) — .NET.
//
// Is the RFC 3161 timestamp token itself authentic? SignedCms verifies the
// CMS signature (CheckSignature(true) — signature only, never the ambient
// trust store), X509Chain with CustomRootTrust builds the chain to a
// CALLER-pinned root with VerificationTime set to the token's own genTime,
// and the signer's extended key usage must be the critical, sole
// id-kp-timeStamping purpose. SignedCms.Decode does not verify, so an
// unreadable token and a not-genuine token produce their own distinct codes.

using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Pruvz.EvidencePacket;

public static class Authority
{
    private const string OidTstInfo = "1.2.840.113549.1.9.16.1.4";
    private const string OidEkuTimeStamping = "1.3.6.1.5.5.7.3.8";

    private static AnchorException Refuse(string code, string message) => new(code, message);

    private static SignedCms ParseSignedData(byte[] der)
    {
        var cms = new SignedCms();
        try
        {
            cms.Decode(der);
        }
        catch (CryptographicException)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", "receipt.token is not a DER ContentInfo carrying SignedData");
        }
        if (cms.ContentInfo.ContentType.Value != OidTstInfo)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"the signed content is {cms.ContentInfo.ContentType.Value}, not a TSTInfo");
        }
        return cms;
    }

    /// <summary>Every certificate embedded in a token, as PEM — pin candidates.</summary>
    public static List<string> EmbeddedCertificates(string token)
    {
        var cms = ParseSignedData(Anchoring.DecodeBase64(token, "receipt.token"));
        return cms.Certificates.Select(certificate => certificate.ExportCertificatePem() + "\n").ToList();
    }

    private static X509Certificate2 SignerCertificate(SignedCms cms)
    {
        if (cms.SignerInfos.Count != 1)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", "a timestamp token carries exactly one SignerInfo");
        }
        var certificate = cms.SignerInfos[0].Certificate;
        if (certificate is null)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", "the signing certificate is not embedded in the token");
        }
        return certificate;
    }

    private static void RequireTimestampingPurpose(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (extension is null)
        {
            throw Refuse("ANCHOR_UNTRUSTED_AUTHORITY", "the signing certificate declares no extended key usage");
        }
        if (!extension.Critical)
        {
            throw Refuse("ANCHOR_UNTRUSTED_AUTHORITY", "the extended key usage of a timestamping certificate must be critical");
        }
        var purposes = extension.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value).ToList();
        if (purposes.Count != 1 || purposes[0] != OidEkuTimeStamping)
        {
            throw Refuse(
                "ANCHOR_UNTRUSTED_AUTHORITY",
                $"the signing certificate's purposes are [{string.Join(", ", purposes)}]; a timestamping certificate carries exactly id-kp-timeStamping");
        }
    }

    private static List<X509Certificate2> LoadPemRoots(IReadOnlyList<string> roots)
    {
        var loaded = new List<X509Certificate2>();
        for (var index = 0; index < roots.Count; index += 1)
        {
            var match = Regex.Match(roots[index], "-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\\r\\n]+-----END CERTIFICATE-----");
            if (!match.Success)
            {
                throw Refuse("ANCHOR_MALFORMED", $"pinned root {index} is not a PEM certificate");
            }
            loaded.Add(X509Certificate2.CreateFromPem(match.Value));
        }
        return loaded;
    }

    public sealed record AuthorityResult(string GenTime, string PolicyOid);

    public static AuthorityResult VerifyTimestampAuthority(
        string token, IReadOnlyList<string>? roots, byte[] imprintInput, IReadOnlyList<string>? policyOids = null)
    {
        if (roots is null || roots.Count == 0)
        {
            throw Refuse("ANCHOR_UNTRUSTED_AUTHORITY", "authority verification requires at least one pinned root certificate");
        }
        if (imprintInput.Length == 0)
        {
            throw Refuse("ANCHOR_MALFORMED", "imprintInput must be the non-empty anchor-input byte string");
        }

        var der = Anchoring.DecodeBase64(token, "receipt.token");
        var parsed = Anchoring.ReadTimestampToken(der);
        var cms = ParseSignedData(der);
        var certificate = SignerCertificate(cms);
        RequireTimestampingPurpose(certificate);

        if (policyOids is not null)
        {
            if (policyOids.Count == 0)
            {
                throw Refuse("ANCHOR_MALFORMED", "policyOids, when given, must be a non-empty array");
            }
            if (!policyOids.Contains(parsed.PolicyOid))
            {
                throw Refuse("ANCHOR_UNTRUSTED_AUTHORITY", $"the token was issued under policy {parsed.PolicyOid}, which the caller does not admit");
            }
        }

        var genTimeMatch = Regex.Match(parsed.GenTime, "^(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d+))?Z$");
        if (!genTimeMatch.Success)
        {
            throw Refuse("ANCHOR_RECEIPT_MALFORMED", $"the token's genTime \"{parsed.GenTime}\" is not a readable instant");
        }
        var genTime = new DateTime(
            int.Parse(genTimeMatch.Groups[1].Value), int.Parse(genTimeMatch.Groups[2].Value), int.Parse(genTimeMatch.Groups[3].Value),
            int.Parse(genTimeMatch.Groups[4].Value), int.Parse(genTimeMatch.Groups[5].Value), int.Parse(genTimeMatch.Groups[6].Value),
            DateTimeKind.Utc);
        var fraction = genTimeMatch.Groups[7].Value;
        if (fraction.Length > 0)
        {
            // Validity at genTime keeps the token's sub-second fraction, as the
            // Python implementation does — one instant, not two.
            genTime = genTime.AddTicks(long.Parse(fraction.PadRight(7, '0')[..7]));
        }

        var trusted = LoadPemRoots(roots);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        foreach (var root in trusted)
        {
            chain.ChainPolicy.CustomTrustStore.Add(root);
        }
        foreach (var extra in cms.Certificates)
        {
            chain.ChainPolicy.ExtraStore.Add(extra);
        }
        chain.ChainPolicy.VerificationTime = genTime;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
            | X509VerificationFlags.IgnoreEndRevocationUnknown
            | X509VerificationFlags.IgnoreCtlNotTimeValid;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // offline by design; the pin is the trust decision
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(OidEkuTimeStamping));
        if (!chain.Build(certificate))
        {
            // A caller may deliberately pin a NON-self-signed certificate (an
            // intermediate) as its trust anchor; CustomRootTrust insists on a
            // self-signed root, so that legitimate pin shape is re-checked
            // explicitly: the chain is rebuilt tolerating an unknown authority,
            // and it is trusted ONLY when a pinned certificate is one of the
            // built-and-signature-verified elements with no other defect.
            using var anchoredChain = new X509Chain();
            anchoredChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in trusted)
            {
                anchoredChain.ChainPolicy.CustomTrustStore.Add(root);
            }
            foreach (var extra in cms.Certificates)
            {
                anchoredChain.ChainPolicy.ExtraStore.Add(extra);
            }
            anchoredChain.ChainPolicy.VerificationTime = genTime;
            anchoredChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            anchoredChain.ChainPolicy.VerificationFlags = chain.ChainPolicy.VerificationFlags
                | X509VerificationFlags.AllowUnknownCertificateAuthority;
            anchoredChain.ChainPolicy.ApplicationPolicy.Add(new Oid(OidEkuTimeStamping));
            // Pin identity is the SHA-256 of the certificate's DER — never the
            // legacy SHA-1 Thumbprint, which an attacker-supplied embedded
            // certificate could collide with.
            var pinnedDigests = trusted.Select(root => Convert.ToHexString(SHA256.HashData(root.RawData))).ToHashSet();
            var acceptable = anchoredChain.Build(certificate)
                || anchoredChain.ChainStatus.All(status =>
                    status.Status is X509ChainStatusFlags.NoError
                        or X509ChainStatusFlags.UntrustedRoot
                        or X509ChainStatusFlags.PartialChain);
            var reachesPin = anchoredChain.ChainElements.Cast<X509ChainElement>()
                .Any(element => pinnedDigests.Contains(Convert.ToHexString(SHA256.HashData(element.Certificate.RawData))));
            if (!acceptable || !reachesPin)
            {
                var detail = string.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()));
                throw Refuse("ANCHOR_UNTRUSTED_AUTHORITY", $"the signing certificate does not chain to a pinned root at the token's genTime ({detail})");
            }
        }

        try
        {
            cms.CheckSignature(true); // signature only — trust was decided by the pinned chain above
        }
        catch (CryptographicException error)
        {
            throw Refuse("ANCHOR_SIGNATURE_INVALID", $"the token's CMS signature does not verify: {error.Message}");
        }

        return new AuthorityResult(parsed.GenTime, parsed.PolicyOid);
    }
}
