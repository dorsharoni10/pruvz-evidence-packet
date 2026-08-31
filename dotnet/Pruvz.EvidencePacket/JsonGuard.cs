// Strict JSON parsing at the trust boundary. One byte string that parses as
// two different documents (duplicate member names) is unusable input, not a
// nuance — conformance/v1 `duplicate-member-refused`. System.Text.Json's
// JsonNode.Parse throws for duplicate properties only via JsonObject
// materialization; walking the tree forces it everywhere.

using System.Text.Json.Nodes;

namespace Pruvz.EvidencePacket;

public static class JsonGuard
{
    public static JsonNode? ParseStrict(string text)
    {
        var node = JsonNode.Parse(text);
        AssertUniqueMembers(node);
        return node;
    }

    private static void AssertUniqueMembers(JsonNode? node)
    {
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
}
