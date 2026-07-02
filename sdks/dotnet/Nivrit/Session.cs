using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nivrit;

public class NivritSession
{
    public NivritClient Client { get; }
    public HelperCrypto Crypto { get; }
    public JsonNode User { get; private set; } = new JsonObject();
    public string PrivateKey { get; private set; } = "";
    private readonly Dictionary<string, string> _projectKeys = new();

    public NivritSession(string baseUrl, string token, HelperCrypto crypto)
    {
        Client = new NivritClient(baseUrl, token);
        Crypto = crypto;
    }

    public async Task AuthenticateAsync(string password)
    {
        User = await Client.GetMeAsync();
        PrivateKey = Crypto.DecryptPrivateKey(
            (string?)User["encrypted_private_key"] ?? throw new InvalidOperationException("missing encrypted_private_key"),
            (string?)User["private_key_nonce"] ?? throw new InvalidOperationException("missing private_key_nonce"),
            password);
    }

    public async Task<IReadOnlyList<JsonObject>> ListProjectsAsync(string orgId)
    {
        var projects = await Client.ListOrgProjectsAsync(orgId);
        var memberships = await Client.ListMyProjectsAsync();
        var membershipMap = new Dictionary<string, JsonNode>();
        foreach (var m in memberships!.AsArray())
            membershipMap[(string?)m!["project_id"]!] = m!;

        var result = new List<JsonObject>();
        foreach (var p in projects!.AsArray())
        {
            var obj = (JsonObject)p!.Deserialize<JsonNode>()!;
            obj["membership"] = membershipMap.TryGetValue((string?)p["id"]!, out var mem) ? mem : null;
            result.Add(obj);
        }
        return result;
    }

    public string GetProjectKey(JsonNode membership)
    {
        var pid = (string?)membership["project_id"] ?? throw new InvalidOperationException("missing project_id");
        if (_projectKeys.TryGetValue(pid, out var cached)) return cached;
        var key = Crypto.DecapsulateProjectKey(
            (string?)membership["encrypted_project_key"] ?? throw new InvalidOperationException("missing encrypted_project_key"),
            PrivateKey);
        _projectKeys[pid] = key;
        return key;
    }

    public async Task<IReadOnlyList<JsonObject>> ListSecretsAsync(string projectId, string environmentId)
    {
        var secrets = await Client.ListSecretsAsync(projectId, environmentId);
        var memberships = await Client.ListMyProjectsAsync();
        JsonNode? membership = null;
        foreach (var m in memberships!.AsArray())
            if ((string?)m!["project_id"] == projectId) { membership = m; break; }
        if (membership == null) throw new InvalidOperationException($"No membership for project {projectId}");
        var projectKey = GetProjectKey(membership);

        var result = new List<JsonObject>();
        foreach (var s in secrets!.AsArray())
        {
            var obj = (JsonObject)s!.Deserialize<JsonNode>()!;
            obj["value"] = Crypto.DecryptValue(
                (string?)s["encrypted_value"]! ?? "",
                (string?)s["nonce"]! ?? "",
                projectKey);
            result.Add(obj);
        }
        return result;
    }

    public static string Base64Encode(byte[] data) => Convert.ToBase64String(data);
    public static byte[] Base64Decode(string s) => Convert.FromBase64String(s);
}
