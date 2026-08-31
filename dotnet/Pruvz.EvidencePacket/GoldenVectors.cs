// The verifier/v1 golden vectors, embedded so an installed package can prove
// itself against the published expectations completely offline (PRUVZ-101).
// The vectors are data, not behavior: nothing in the verifier reads them to
// produce an answer.

namespace Pruvz.EvidencePacket;

public static class GoldenVectors
{
    /// <summary>The raw JSON text of the published verifier/v1 golden-vectors.json.</summary>
    public static string VerifierV1Json()
    {
        using var stream = typeof(GoldenVectors).Assembly.GetManifestResourceStream("pruvz:verifier/v1/golden-vectors.json")
            ?? throw new InvalidOperationException("embedded resource pruvz:verifier/v1/golden-vectors.json is missing from this build");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
