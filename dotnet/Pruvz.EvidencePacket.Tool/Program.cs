// The offline Evidence Packet verifier as a dotnet tool (PRUVZ-101).
//
// Usage: pruvz-verify <bundle.json> --issuer <issuer> --root <thumbprint>
//                     [--tenant <tenantId>] [--tsa-roots <pem-file>]
//                     [--tsa-policy <oid> ...] [--state <state.json>]
//                     [--no-update-state] [--json]
//
// The argument surface, output and exit codes mirror the npm CLI
// (bin/verify.mjs): 0 FULLY_VERIFIED, 3 PARTIALLY_VERIFIED, 1 NOT_VERIFIED,
// 2 usage or unreadable input. The trust anchor (--issuer and --root) is the
// pin established out of band (docs/TRUST-REGISTRY.md section 4) and is
// mandatory: there is no pinless mode, and nothing is ever fetched from a
// Pruvz deployment or website.

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Pruvz.EvidencePacket;

var usageText =
    "Usage: pruvz-verify <bundle.json> --issuer <issuer> --root <thumbprint>\n" +
    "                    [--tenant <tenantId>] [--tsa-roots <pem-file>]\n" +
    "                    [--tsa-policy <oid> ...] [--state <state.json>]\n" +
    "                    [--no-update-state] [--json]";

int Usage()
{
    Console.Error.WriteLine(usageText);
    return 2;
}

string? bundleFile = null;
string? issuer = null;
string? root = null;
string? tenant = null;
string? tsaRootsFile = null;
var tsaPolicyOids = new List<string>();
string? stateFile = null;
var updateState = true;
var asJson = false;

for (var index = 0; index < args.Length; index += 1)
{
    var arg = args[index];
    string? Next()
    {
        index += 1;
        return index < args.Length ? args[index] : null;
    }
    string? value;
    if (arg == "--issuer") { if ((value = Next()) is null) return Usage(); issuer = value; }
    else if (arg == "--root") { if ((value = Next()) is null) return Usage(); root = value; }
    else if (arg == "--tenant") { if ((value = Next()) is null) return Usage(); tenant = value; }
    else if (arg == "--tsa-roots") { if ((value = Next()) is null) return Usage(); tsaRootsFile = value; }
    else if (arg == "--tsa-policy") { if ((value = Next()) is null) return Usage(); tsaPolicyOids.Add(value); }
    else if (arg == "--state") { if ((value = Next()) is null) return Usage(); stateFile = value; }
    else if (arg == "--no-update-state") { updateState = false; }
    else if (arg == "--json") { asJson = true; }
    else if (arg.StartsWith("--")) { return Usage(); }
    else if (bundleFile is null) { bundleFile = arg; }
    else { return Usage(); }
}

if (bundleFile is null || issuer is null || root is null)
{
    return Usage();
}

JsonNode? ReadJson(string file, string what)
{
    try
    {
        // One byte string that parses as two different documents (duplicate
        // member names) is unusable input at a trust boundary, not a nuance —
        // conformance/v1 `duplicate-member-refused`.
        return JsonGuard.ParseStrict(File.ReadAllText(file));
    }
    catch (Exception error)
    {
        Console.Error.WriteLine($"FAIL  {what} {file} is not readable as JSON: {error.Message}");
        Environment.Exit(2);
        throw; // unreachable
    }
}

var bundle = ReadJson(bundleFile, "bundle");
JsonObject? state = null;
if (stateFile is not null && File.Exists(stateFile))
{
    state = ReadJson(stateFile, "state") as JsonObject;
    if (state is null)
    {
        Console.Error.WriteLine($"FAIL  state {stateFile} is not readable as JSON: a state document is an object");
        return 2;
    }
}

List<string>? tsaRoots = null;
if (tsaRootsFile is not null)
{
    var pem = File.ReadAllText(tsaRootsFile);
    tsaRoots = Regex.Matches(pem, "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----")
        .Select(match => match.Value)
        .ToList();
    if (tsaRoots.Count == 0)
    {
        Console.Error.WriteLine($"FAIL  {tsaRootsFile} contains no PEM certificates");
        return 2;
    }
}

JsonObject report;
try
{
    report = Verify.VerifyBundle(
        bundle,
        new JsonObject { ["issuer"] = issuer, ["root"] = root },
        tenant,
        tsaRoots,
        tsaPolicyOids.Count > 0 ? tsaPolicyOids : null,
        state);
}
catch (Exception error)
{
    var code = error switch
    {
        VerifierException typed => typed.Code,
        TrustRegistryException typed => typed.Code,
        EvidenceLogException typed => typed.Code,
        AnchorException typed => typed.Code,
        CommitmentException typed => typed.Code,
        _ => "ERROR",
    };
    Console.Error.WriteLine($"FAIL  {code}  {error.Message}");
    return 2;
}

var writeOptions = new JsonSerializerOptions { WriteIndented = true };
var verdict = (string?)report["verdict"];

if (stateFile is not null && updateState && verdict != "NOT_VERIFIED")
{
    File.WriteAllText(stateFile, $"{report["state"]!.ToJsonString(writeOptions)}\n");
}

if (asJson)
{
    Console.WriteLine(report.ToJsonString(writeOptions));
}
else
{
    Console.WriteLine($"Verdict: {verdict}");
    Console.WriteLine("");
    Console.WriteLine("Dimensions:");
    foreach (var pair in (JsonObject)report["dimensions"]!)
    {
        Console.WriteLine($"  {pair.Key.PadRight(18)} {(string?)((JsonObject)pair.Value!)["status"]}");
    }
    var evidence = (JsonArray)report["evidence"]!;
    if (evidence.Count > 0)
    {
        Console.WriteLine("");
        Console.WriteLine("Evidence:");
        foreach (var node in evidence)
        {
            var entry = (JsonObject)node!;
            var sequence = entry["sequence"] is null ? "?" : entry["sequence"]!.ToJsonString();
            var seal = entry["seal"] is JsonObject sealObj ? (string?)sealObj["status"] : null;
            var inclusion = entry["inclusion"] is JsonObject inclusionObj ? (string?)inclusionObj["status"] : null;
            Console.WriteLine(
                $"  {sequence.PadLeft(3)}  {(string?)entry["evidenceId"]}  " +
                $"commitment={(string?)entry["commitment"]}  seal={seal}  inclusion={inclusion}");
        }
    }
    var reasonCodes = (JsonArray)report["reasonCodes"]!;
    if (reasonCodes.Count > 0)
    {
        Console.WriteLine("");
        Console.WriteLine($"Reason codes: {string.Join(", ", reasonCodes.Select(code => (string?)code))}");
    }
    foreach (var node in (JsonArray)report["explanations"]!)
    {
        var explanation = (JsonObject)node!;
        Console.WriteLine($"  - [{(string?)explanation["code"]}] {(string?)explanation["message"]}");
    }
}

return verdict == "FULLY_VERIFIED" ? 0 : verdict == "PARTIALLY_VERIFIED" ? 3 : 1;
