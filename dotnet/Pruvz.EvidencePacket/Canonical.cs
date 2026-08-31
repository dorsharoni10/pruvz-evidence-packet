// Canonical commitment, format version 1 — independent .NET implementation.
//
// Implemented from docs/COMMITMENT.md (PRUVZ-97). Shares no code with the
// Node reference implementation or with pruvz-core; agreement is proven byte
// for byte against commitment/v1/golden-vectors.json.
//
// JSON documents are handled as System.Text.Json JsonNode trees. Numbers keep
// their raw text (JsonElement), so the value model can judge the VALUE — 5,
// 5.0 and 5e0 denote one integer; -0 and 2.5 are refusals — without ever
// routing a committed number through double formatting.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Pruvz.EvidencePacket;

public sealed class CommitmentException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class Canonical
{
    public const string CommitmentVersion = "1";
    public static readonly string[] DigestSuites = ["sha-256"];
    public static readonly string[] CommitmentKinds = ["evidence-item", "evidence-packet"];

    private const string DomainTag = "pruvz.ai/commitment";
    private const char Separator = '\u0000';
    private const long MaxSafeInteger = 9007199254740991;

    private static CommitmentException Refuse(string code, string message) => new(code, message);

    private static void SerializeString(StringBuilder output, string value, string path)
    {
        output.Append('"');
        for (var index = 0; index < value.Length; index += 1)
        {
            var character = value[index];
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    throw Refuse("LONE_SURROGATE", $"{path}: unpaired high surrogate at index {index}");
                }
                output.Append(character).Append(value[index + 1]);
                index += 1;
                continue;
            }
            if (char.IsLowSurrogate(character))
            {
                throw Refuse("LONE_SURROGATE", $"{path}: unpaired low surrogate at index {index}");
            }
            switch (character)
            {
                case '"': output.Append("\\\""); break;
                case '\\': output.Append("\\\\"); break;
                case '\b': output.Append("\\b"); break;
                case '\f': output.Append("\\f"); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                default:
                    if (character < 0x20)
                    {
                        output.Append("\\u").Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        output.Append(character);
                    }
                    break;
            }
        }
        output.Append('"');
    }

    /// <summary>
    /// The committed integer a JSON number denotes, judged by VALUE: an exact
    /// integer within the safe range, however it was spelled. A non-integral
    /// value, a negative zero or an out-of-range integer is a refusal.
    /// </summary>
    private static string SerializeNumber(JsonElement element, string path)
    {
        var raw = element.GetRawText();
        // Judge by value, never by spelling: 5, 5.0 and 5e0 denote one
        // integer. decimal covers every judgeable spelling exactly; a value
        // beyond its range cannot be a safe integer either way.
        if (decimal.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var exact))
        {
            if (raw.StartsWith("-0", StringComparison.Ordinal) && exact == 0m)
            {
                throw Refuse("NON_INTEGER_NUMBER", $"{path}: only integers may be committed (got -0)");
            }
            if (decimal.Truncate(exact) != exact)
            {
                throw Refuse(
                    "NON_INTEGER_NUMBER",
                    $"{path}: only integers may be committed (got {raw}); precision-sensitive values are committed as canonical decimal strings");
            }
            if (exact > MaxSafeInteger || exact < -MaxSafeInteger)
            {
                throw Refuse("INTEGER_OUT_OF_RANGE", $"{path}: integer {raw} is outside the safe integer range");
            }
            return ((long)exact).ToString(CultureInfo.InvariantCulture);
        }
        // Out of decimal's range (e.g. 1e999): whatever it is, it is not a safe integer.
        throw Refuse("INTEGER_OUT_OF_RANGE", $"{path}: integer {raw} is outside the safe integer range");
    }

    private static void SerializeValue(StringBuilder output, JsonNode? value, string path)
    {
        switch (value)
        {
            case null:
                output.Append("null");
                return;
            case JsonObject obj:
            {
                output.Append('{');
                var first = true;
                foreach (var key in obj.Select(pair => pair.Key).OrderBy(key => key, StringComparer.Ordinal))
                {
                    if (!first) output.Append(',');
                    first = false;
                    SerializeString(output, key, $"{path}/{key}");
                    output.Append(':');
                    SerializeValue(output, obj[key], $"{path}/{key}");
                }
                output.Append('}');
                return;
            }
            case JsonArray array:
            {
                output.Append('[');
                for (var index = 0; index < array.Count; index += 1)
                {
                    if (index > 0) output.Append(',');
                    SerializeValue(output, array[index], $"{path}/{index}");
                }
                output.Append(']');
                return;
            }
            case JsonValue leaf:
            {
                if (leaf.TryGetValue<JsonElement>(out var element))
                {
                    switch (element.ValueKind)
                    {
                        case JsonValueKind.String:
                            SerializeString(output, element.GetString()!, path);
                            return;
                        case JsonValueKind.Number:
                            output.Append(SerializeNumber(element, path));
                            return;
                        case JsonValueKind.True:
                            output.Append("true");
                            return;
                        case JsonValueKind.False:
                            output.Append("false");
                            return;
                        case JsonValueKind.Null:
                            output.Append("null");
                            return;
                    }
                }
                // A JsonValue built in memory (string/bool wrappers).
                if (leaf.TryGetValue<string>(out var text))
                {
                    SerializeString(output, text, path);
                    return;
                }
                if (leaf.TryGetValue<bool>(out var flag))
                {
                    output.Append(flag ? "true" : "false");
                    return;
                }
                if (leaf.TryGetValue<long>(out var integer))
                {
                    if (Math.Abs(integer) > MaxSafeInteger)
                    {
                        throw Refuse("INTEGER_OUT_OF_RANGE", $"{path}: integer {integer} is outside the safe integer range");
                    }
                    output.Append(integer.ToString(CultureInfo.InvariantCulture));
                    return;
                }
                throw Refuse("UNSUPPORTED_VALUE", $"{path}: this value cannot be committed");
            }
            default:
                throw Refuse("UNSUPPORTED_VALUE", $"{path}: this value cannot be committed");
        }
    }

    public static byte[] Canonicalize(JsonNode? document)
    {
        var output = new StringBuilder();
        SerializeValue(output, document, "$");
        return Encoding.UTF8.GetBytes(output.ToString());
    }

    public static byte[] CommitmentInput(string kind, JsonNode? document)
    {
        if (!CommitmentKinds.Contains(kind))
        {
            throw Refuse("UNKNOWN_KIND", $"Unknown commitment kind \"{kind}\".");
        }
        var header = string.Join(Separator, DomainTag, CommitmentVersion, kind, "");
        return [.. Encoding.UTF8.GetBytes(header), .. Canonicalize(document)];
    }

    public static string CommitmentDigest(string kind, JsonNode? document, string? suite = null)
    {
        suite ??= DigestSuites[0];
        if (!DigestSuites.Contains(suite))
        {
            throw Refuse("UNKNOWN_DIGEST_SUITE", $"Unknown digest suite \"{suite}\".");
        }
        return "sha256:" + Convert.ToHexString(SHA256.HashData(CommitmentInput(kind, document))).ToLowerInvariant();
    }

    public static void RequireSupported(string? commitmentVersion, string? digestSuite = null)
    {
        digestSuite ??= DigestSuites[0];
        if (commitmentVersion != CommitmentVersion)
        {
            throw Refuse("UNKNOWN_COMMITMENT_VERSION", $"Unknown commitment version \"{commitmentVersion}\".");
        }
        if (!DigestSuites.Contains(digestSuite))
        {
            throw Refuse("UNKNOWN_DIGEST_SUITE", $"Unknown digest suite \"{digestSuite}\".");
        }
    }

    private static readonly Regex ExactDecimal = new("^-?(0|[1-9][0-9]*)(\\.[0-9]+)?$", RegexOptions.Compiled);

    public static string CanonicalDecimal(JsonNode? node)
    {
        if (node is not JsonValue leaf || !leaf.TryGetValue<string>(out var text))
        {
            throw Refuse("NON_CANONICAL_DECIMAL", "An exact decimal must be a string");
        }
        return CanonicalDecimal(text);
    }

    public static string CanonicalDecimal(string text)
    {
        if (!ExactDecimal.IsMatch(text))
        {
            throw Refuse("NON_CANONICAL_DECIMAL", $"\"{text}\" is not an exact decimal");
        }
        var parts = text.Split('.', 2);
        var integer = parts[0];
        var fraction = parts.Length > 1 ? parts[1].TrimEnd('0') : "";
        if (integer == "-0" && fraction.Length == 0)
        {
            throw Refuse("NEGATIVE_ZERO", "Negative zero has no canonical decimal form; write 0");
        }
        return fraction.Length == 0 ? integer : $"{integer}.{fraction}";
    }

    private static readonly Regex UtcTimestamp = new("^(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(?:\\.(\\d+))?Z$", RegexOptions.Compiled);

    public static string CanonicalTimestamp(string? text)
    {
        if (text is null)
        {
            throw Refuse("NON_UTC_TIMESTAMP", "A UTC timestamp must be a string");
        }
        var match = UtcTimestamp.Match(text);
        if (!match.Success)
        {
            throw Refuse("NON_UTC_TIMESTAMP", $"\"{text}\" is not a UTC timestamp of the form YYYY-MM-DDTHH:MM:SS[.fraction]Z");
        }
        var fraction = match.Groups[2].Value.TrimEnd('0');
        return fraction.Length == 0 ? $"{match.Groups[1].Value}Z" : $"{match.Groups[1].Value}.{fraction}Z";
    }

    public static bool IsMoney(JsonNode? value) =>
        value is JsonObject obj && obj.TryGetPropertyValue("currency", out var currency) &&
        currency is JsonValue leaf && leaf.TryGetValue<JsonElement>(out var element) &&
        element.ValueKind == JsonValueKind.String;

    private static readonly string[] MoneyMembers = ["amount", "amountExact", "currency"];
    private static readonly Regex Currency = new("^[A-Z]{3}$", RegexOptions.Compiled);

    public static JsonObject CanonicalMoney(JsonObject money, string path)
    {
        if (!IsMoney(money))
        {
            throw Refuse("INVALID_MONEY", $"{path}: not a money value");
        }
        var amountExact = money.TryGetPropertyValue("amountExact", out var exactNode) && exactNode is JsonValue exactLeaf &&
            exactLeaf.TryGetValue<JsonElement>(out var exactElement) && exactElement.ValueKind == JsonValueKind.String
                ? exactElement.GetString()
                : null;
        if (amountExact is null)
        {
            throw Refuse("MONEY_WITHOUT_EXACT_AMOUNT", $"{path}: money must carry amountExact (packet format 1.4.0 or later)");
        }
        var unknown = money.Select(pair => pair.Key).Where(member => !MoneyMembers.Contains(member)).ToList();
        if (unknown.Count > 0)
        {
            throw Refuse("INVALID_MONEY", $"{path}: a money value carries only amount, amountExact, currency; got {string.Join(", ", unknown)}");
        }
        var currency = money["currency"]!.GetValue<string>();
        if (!Currency.IsMatch(currency))
        {
            throw Refuse("INVALID_CURRENCY", $"{path}: currency must be a three-letter uppercase ISO 4217 code");
        }
        return new JsonObject { ["amount"] = CanonicalDecimal(amountExact), ["currency"] = currency };
    }

    private static JsonNode? NormalizePacketValue(JsonNode? value, string path, string? key)
    {
        if (value is JsonObject obj)
        {
            if (IsMoney(obj))
            {
                return CanonicalMoney(obj, path);
            }
            var replacement = new JsonObject();
            foreach (var pair in obj.ToList())
            {
                replacement[pair.Key] = NormalizePacketValue(pair.Value?.DeepClone(), $"{path}/{pair.Key}", pair.Key);
            }
            return replacement;
        }
        if (value is JsonArray array)
        {
            var replacement = new JsonArray();
            for (var index = 0; index < array.Count; index += 1)
            {
                replacement.Add(NormalizePacketValue(array[index]?.DeepClone(), $"{path}/{index}", null));
            }
            return replacement;
        }
        if (value is JsonValue leaf && key is not null && key.EndsWith("AtUtc", StringComparison.Ordinal) &&
            leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.String)
        {
            return CanonicalTimestamp(element.GetString());
        }
        return value;
    }

    public static JsonObject EvidencePacketDocument(JsonObject source)
    {
        var tenantId = StringOf(source, "tenantId");
        if (string.IsNullOrEmpty(tenantId))
        {
            throw Refuse("MISSING_BINDING", "A commitment must bind a tenantId");
        }
        if (source.TryGetPropertyValue("packet", out var packetNode) is false || packetNode is not JsonObject packet)
        {
            throw Refuse("INVALID_DOCUMENT", "packet must be the parsed Evidence Packet document");
        }
        var actionId = packet["action"] is JsonObject action ? StringOf(action, "actionId") : null;
        if (actionId is null)
        {
            throw Refuse("MISSING_BINDING", "packet.action.actionId is required to bind the commitment");
        }
        return new JsonObject
        {
            ["binding"] = new JsonObject { ["actionId"] = actionId, ["tenantId"] = tenantId },
            ["content"] = NormalizePacketValue(packet.DeepClone(), "$", null),
        };
    }

    public static readonly string[] EvidenceItemFields =
    [
        "clientOperationId", "evidenceId", "occurredAtUtc", "payloadMetadata", "recordedAtUtc",
        "runId", "schemaVersion", "sequence", "source", "sourceReference", "summary", "trustLevel", "type",
    ];

    public static JsonObject EvidenceItemDocument(JsonObject source)
    {
        var tenantId = StringOf(source, "tenantId");
        var actionId = StringOf(source, "actionId");
        if (string.IsNullOrEmpty(tenantId))
        {
            throw Refuse("MISSING_BINDING", "A commitment must bind a tenantId");
        }
        if (string.IsNullOrEmpty(actionId))
        {
            throw Refuse("MISSING_BINDING", "A commitment must bind an actionId");
        }
        if (source.TryGetPropertyValue("item", out var itemNode) is false || itemNode is not JsonObject item)
        {
            throw Refuse("INVALID_DOCUMENT", "item must be the evidence item record");
        }
        var content = new JsonObject();
        foreach (var field in EvidenceItemFields)
        {
            if (!item.TryGetPropertyValue(field, out var value))
            {
                throw Refuse("MISSING_FIELD", $"item.{field} is required: the commitment covers every field of the item");
            }
            content[field] = field.EndsWith("AtUtc", StringComparison.Ordinal)
                ? CanonicalTimestamp(value is JsonValue timeLeaf && timeLeaf.TryGetValue<string>(out var time) ? time : null)
                : value?.DeepClone();
        }
        return new JsonObject
        {
            ["binding"] = new JsonObject { ["actionId"] = actionId, ["tenantId"] = tenantId },
            ["content"] = content,
        };
    }

    public static string? StringOf(JsonObject obj, string member) =>
        obj.TryGetPropertyValue(member, out var node) && node is JsonValue leaf &&
        leaf.TryGetValue<JsonElement>(out var element) && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : node is JsonValue direct && direct.TryGetValue<string>(out var text) ? text : null;
}
