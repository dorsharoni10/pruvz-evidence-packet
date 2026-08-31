// Packet validation — JSON Schema (draft 2020-12, JsonSchema.Net) plus the
// packet-level consistency rules JSON Schema cannot express, ported from the
// published specification (docs/CONFORMANCE.md and the packet format docs).

using System.Text.Json.Nodes;
using Json.Schema;

namespace Pruvz.EvidencePacket;

public static class Validator
{
    public static readonly string[] SupportedVersions = ["1.5.0", "1.4.0", "1.3.0", "1.2.0", "1.1.0", "1.0.0"];

    // null (the default) reads the published schemas embedded in this assembly,
    // so an installed package is self-sufficient offline (PRUVZ-101). The
    // conformance harness points this at the repository's schema/ directory
    // instead, so repository-mode runs judge the working-tree bytes.
    public static string? SchemaRoot = null;

    private static readonly Dictionary<string, (JsonSchema Schema, EvaluationOptions Options)> Compiled = [];

    private static bool SupportsReverification(string version)
    {
        var parts = version.Split('.');
        return int.Parse(parts[0]) > 1 || (int.Parse(parts[0]) == 1 && int.Parse(parts[1]) >= 3);
    }

    private static bool SupportsExactAmount(string version)
    {
        var parts = version.Split('.');
        return int.Parse(parts[0]) > 1 || (int.Parse(parts[0]) == 1 && int.Parse(parts[1]) >= 4);
    }

    private static (JsonSchema Schema, EvaluationOptions Options) CreateValidator(string version)
    {
        if (!SupportedVersions.Contains(version))
        {
            throw new ArgumentException($"Unsupported packet format version \"{version}\"");
        }
        if (!Compiled.TryGetValue(version, out var cached))
        {
            var options = new EvaluationOptions { OutputFormat = OutputFormat.List };
            foreach (var name in new[] { "action.schema.json", "evidence.schema.json" })
            {
                SchemaRegistry.Global.Register(JsonSchema.FromText(SchemaText(version, name)));
            }
            var packetSchema = JsonSchema.FromText(SchemaText(version, "evidence-packet.schema.json"));
            SchemaRegistry.Global.Register(packetSchema);
            cached = (packetSchema, options);
            Compiled[version] = cached;
        }
        return cached;
    }

    private static string SchemaText(string version, string name)
    {
        if (SchemaRoot is not null)
        {
            return File.ReadAllText(Path.GetFullPath(Path.Combine(SchemaRoot, $"v{version}", name)));
        }
        var resource = $"pruvz:schema/v{version}/{name}";
        using var stream = typeof(Validator).Assembly.GetManifestResourceStream(resource)
            ?? throw new InvalidOperationException($"embedded schema resource {resource} is missing from this build");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static JsonObject ConsistencyError(string instancePath, string message) => new()
    {
        ["instancePath"] = instancePath,
        ["keyword"] = "packetConsistency",
        ["message"] = message,
    };

    private static void MoneyValues(JsonNode? value, string pointer, List<(string Pointer, JsonObject Money)> found)
    {
        if (value is JsonArray array)
        {
            for (var index = 0; index < array.Count; index += 1)
            {
                MoneyValues(array[index], $"{pointer}/{index}", found);
            }
        }
        else if (value is JsonObject obj)
        {
            if (Canonical.IsMoney(obj))
            {
                found.Add((pointer, obj));
            }
            foreach (var pair in obj)
            {
                MoneyValues(pair.Value, $"{pointer}/{pair.Key}", found);
            }
        }
    }

    private static bool RepresentationsAgree(JsonObject money)
    {
        try
        {
            var exact = Canonical.StringOf(money, "amountExact");
            if (exact is null)
            {
                return false;
            }
            var canonical = Canonical.CanonicalDecimal(exact);
            var amountNode = money["amount"];
            if (amountNode is not JsonValue leaf || !leaf.TryGetValue<System.Text.Json.JsonElement>(out var element)
                || element.ValueKind != System.Text.Json.JsonValueKind.Number)
            {
                return false;
            }
            // Numeric comparison, exactly as specified: the JSON number is the
            // nearest double to the exact amount.
            return double.Parse(canonical, System.Globalization.CultureInfo.InvariantCulture) == element.GetDouble();
        }
        catch (Exception exception) when (exception is CommitmentException or FormatException or OverflowException)
        {
            return false;
        }
    }

    public static List<JsonObject> PacketConsistencyErrors(JsonObject packet, string version)
    {
        var errors = new List<JsonObject>();
        var action = (JsonObject)packet["action"]!;
        var evidence = (JsonObject)packet["evidence"]!;
        var items = (JsonArray)evidence["items"]!;
        var reverification = SupportsReverification(version);

        if (Canonical.StringOf(action, "actionId") != Canonical.StringOf(evidence, "actionId"))
        {
            errors.Add(ConsistencyError("/evidence/actionId", "must equal /action/actionId"));
        }
        for (var index = 0; index < items.Count; index += 1)
        {
            if (Registry.IntegerOf(((JsonObject)items[index]!)["sequence"]) != index + 1)
            {
                errors.Add(ConsistencyError($"/evidence/items/{index}/sequence", $"must be {index + 1}"));
            }
        }
        var seen = new Dictionary<string, int>();
        for (var index = 0; index < items.Count; index += 1)
        {
            var id = Canonical.StringOf((JsonObject)items[index]!, "evidenceId")!;
            if (!seen.TryAdd(id, index))
            {
                errors.Add(ConsistencyError($"/evidence/items/{index}/evidenceId", "must be unique"));
            }
        }

        var decisionItems = items.Cast<JsonObject>().Where(item => Canonical.StringOf(item!, "type") == "HUMAN_REVIEW_DECISION").ToList();
        if (!action.ContainsKey("review"))
        {
            if (Canonical.StringOf(action, "reviewState") == "DECIDED" && decisionItems.Count == 0)
            {
                errors.Add(ConsistencyError("/action/reviewState", "DECIDED requires a HUMAN_REVIEW_DECISION item"));
            }
            if (decisionItems.Count > 0 && Canonical.StringOf(action, "reviewState") != "DECIDED")
            {
                errors.Add(ConsistencyError("/action/reviewState", "must be DECIDED"));
            }
        }
        else
        {
            errors.AddRange(ReviewConsistencyErrors(action, decisionItems!, reverification));
        }

        var review = action["review"] as JsonObject;
        var resolvedExternally = review is not null
            && ((JsonArray)review["decisions"]!).Cast<JsonObject>().Any(decision => Canonical.StringOf(decision!, "decision") == "RESOLVED_EXTERNALLY");
        if (reverification && action["reverificationTiming"] is not null && !resolvedExternally)
        {
            errors.Add(ConsistencyError("/action/reverificationTiming", "requires a RESOLVED_EXTERNALLY decision"));
        }
        if (reverification && items.Cast<JsonObject>().Any(item => Canonical.StringOf(item!, "type") == "FOLLOW_UP_INDEPENDENT_READBACK"))
        {
            if (!resolvedExternally)
            {
                errors.Add(ConsistencyError("/action/review", "FOLLOW_UP_INDEPENDENT_READBACK requires RESOLVED_EXTERNALLY"));
            }
            if (action["reverificationTiming"] is null)
            {
                errors.Add(ConsistencyError("/action/reverificationTiming", "the fresh window must be recorded"));
            }
        }

        var executionStatus = Canonical.StringOf(action, "executionStatus");
        var started = action["executionStartedAtUtc"];
        var completed = action["executionCompletedAtUtc"];
        if (executionStatus == "RECEIVED" && started is not null)
        {
            errors.Add(ConsistencyError("/action/executionStartedAtUtc", "must be null while RECEIVED"));
        }
        if (executionStatus == "EXECUTING" && started is null)
        {
            errors.Add(ConsistencyError("/action/executionStartedAtUtc", "must be set when EXECUTING"));
        }
        if (executionStatus == "COMPLETED" && completed is null)
        {
            errors.Add(ConsistencyError("/action/executionCompletedAtUtc", "must be set when COMPLETED"));
        }
        if (executionStatus != "COMPLETED" && completed is not null)
        {
            errors.Add(ConsistencyError("/action/executionCompletedAtUtc", $"must be null while {executionStatus}"));
        }
        if (Canonical.StringOf(action, "verificationStatus") != "NOT_STARTED" && executionStatus != "COMPLETED")
        {
            errors.Add(ConsistencyError("/action/verificationStatus", "requires executionStatus COMPLETED"));
        }
        if (action["mismatch"] is JsonObject mismatch
            && Canonical.StringOf(mismatch, "mismatchReason") == "EXPECTED_OUTCOME_ABSENT_AFTER_DEADLINE"
            && action["verificationTiming"] is JsonObject timing
            && timing["deadlineAtUtc"] is null)
        {
            errors.Add(ConsistencyError("/action/mismatch/mismatchReason", "requires a resolved verificationTiming.deadlineAtUtc"));
        }

        if (SupportsExactAmount(version))
        {
            var monies = new List<(string Pointer, JsonObject Money)>();
            MoneyValues(action, "/action", monies);
            foreach (var (pointer, money) in monies)
            {
                if (!RepresentationsAgree(money))
                {
                    errors.Add(ConsistencyError($"{pointer}/amountExact", "must denote the same amount as the JSON number beside it"));
                }
            }
        }
        return errors;
    }

    private static List<JsonObject> ReviewConsistencyErrors(JsonObject action, List<JsonObject> decisionItems, bool reverification)
    {
        var errors = new List<JsonObject>();
        var review = action["review"] as JsonObject;
        if (review is null)
        {
            if (decisionItems.Count > 0)
            {
                errors.Add(ConsistencyError("/action/review", "must be present when the timeline carries a HUMAN_REVIEW_DECISION item"));
            }
            return errors;
        }
        var decisions = ((JsonArray)review["decisions"]!).Cast<JsonObject>().ToList();
        if (decisions.Count != decisionItems.Count)
        {
            errors.Add(ConsistencyError("/action/review/decisions", "must list exactly one decision per HUMAN_REVIEW_DECISION item"));
        }
        for (var index = 0; index < decisions.Count; index += 1)
        {
            var decision = decisions[index]!;
            var item = index < decisionItems.Count ? decisionItems[index] : null;
            if (item is null
                || Canonical.StringOf(item, "evidenceId") != Canonical.StringOf(decision, "evidenceId")
                || Registry.IntegerOf(item["sequence"]) != Registry.IntegerOf(decision["evidenceSequence"]))
            {
                errors.Add(ConsistencyError($"/action/review/decisions/{index}/evidenceId", "must name the matching HUMAN_REVIEW_DECISION item"));
            }
            if (index > 0 && Canonical.StringOf(decisions[index - 1]!, "newReviewState") != Canonical.StringOf(decision, "previousReviewState"))
            {
                var workerReturn = reverification
                    && Canonical.StringOf(decisions[index - 1]!, "decision") == "RESOLVED_EXTERNALLY"
                    && Canonical.StringOf(decision, "previousReviewState") == "PENDING_REVIEW";
                if (!workerReturn)
                {
                    errors.Add(ConsistencyError($"/action/review/decisions/{index}/previousReviewState", "must equal the previous decision's newReviewState"));
                }
            }
        }
        if (decisions.Count > 0 && Canonical.StringOf(decisions[0]!, "previousReviewState") != "PENDING_REVIEW")
        {
            errors.Add(ConsistencyError("/action/review/decisions/0/previousReviewState", "must be PENDING_REVIEW"));
        }
        var last = decisions.Count > 0 ? decisions[^1] : null;
        var latest = review["latestDecision"];
        var latestMatches = last is null ? latest is null : latest is not null && JsonNode.DeepEquals(latest, last);
        if (!latestMatches)
        {
            errors.Add(ConsistencyError("/action/review/latestDecision", "must equal the last entry of decisions"));
        }
        var expectedState = last is null ? "PENDING_REVIEW" : Canonical.StringOf(last, "newReviewState");
        if (Canonical.StringOf(action, "reviewState") != expectedState)
        {
            var verificationStatus = Canonical.StringOf(action, "verificationStatus");
            var reviewState = Canonical.StringOf(action, "reviewState");
            var workerMoved = reverification && last is not null
                && Canonical.StringOf(last, "decision") == "RESOLVED_EXTERNALLY"
                && ((reviewState == "DECIDED" && verificationStatus == "VERIFIED")
                    || (reviewState == "PENDING_REVIEW" && (verificationStatus == "OUTCOME_MISMATCH" || verificationStatus == "VERIFICATION_FAILED")));
            if (!workerMoved)
            {
                errors.Add(ConsistencyError("/action/reviewState", "must follow the latest decision"));
            }
        }
        if (reverification)
        {
            var lastDecision = last is null ? null : Canonical.StringOf(last, "decision");
            if (Canonical.StringOf(action, "verificationStatus") == "VERIFIED" && lastDecision != "RESOLVED_EXTERNALLY")
            {
                errors.Add(ConsistencyError("/action/review", "a VERIFIED action carries a review only after RESOLVED_EXTERNALLY"));
            }
            if (review["independentlyConfirmed"] is JsonValue confirmed && confirmed.TryGetValue<bool>(out var isConfirmed) && isConfirmed && lastDecision != "RESOLVED_EXTERNALLY")
            {
                errors.Add(ConsistencyError("/action/review/independentlyConfirmed", "true requires RESOLVED_EXTERNALLY"));
            }
        }
        return errors;
    }

    public sealed record ValidationOutcome(bool Valid, string Version, List<JsonObject> Errors);

    public static ValidationOutcome ValidatePacket(JsonNode? node)
    {
        var declared = node is JsonObject packet ? Canonical.StringOf(packet, "packetFormatVersion") : null;
        var version = declared is not null && SupportedVersions.Contains(declared) ? declared : SupportedVersions[0];
        var (schema, options) = CreateValidator(version);
        var results = schema.Evaluate(System.Text.Json.JsonSerializer.SerializeToElement(node), options);
        if (!results.IsValid)
        {
            var errors = results.Details
                .Where(detail => detail.Errors is not null && detail.Errors.Count > 0)
                .SelectMany(detail => detail.Errors!.Select(error => new JsonObject
                {
                    ["instancePath"] = detail.InstanceLocation.ToString(),
                    ["message"] = error.Value,
                }))
                .ToList();
            return new ValidationOutcome(false, version, errors);
        }
        var consistency = PacketConsistencyErrors((JsonObject)node!, version);
        return new ValidationOutcome(consistency.Count == 0, version, consistency);
    }
}
