using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nivrit;

public class NivritClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public NivritClient(string baseUrl, string token)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    private async Task<JsonNode?> RequestAsync(HttpMethod method, string path, object? body = null)
    {
        var req = new HttpRequestMessage(method, $"{_baseUrl}{path}");
        if (body != null)
            req.Content = JsonContent.Create(body);
        var resp = await _http.SendAsync(req);
        var text = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Nivrit API error {(int)resp.StatusCode}: {text}");
        return string.IsNullOrEmpty(text) ? null : JsonNode.Parse(text);
    }

    public Task<JsonNode> GetMeAsync() => RequestAsync(HttpMethod.Get, "/users/me")!;
    public Task<JsonNode> ListOrgsAsync() => RequestAsync(HttpMethod.Get, "/users/me/orgs")!;
    public Task<JsonNode> ListMyProjectsAsync() => RequestAsync(HttpMethod.Get, "/users/me/projects")!;
    public Task<JsonNode> ListOrgProjectsAsync(string orgId) => RequestAsync(HttpMethod.Get, $"/orgs/{Uri.EscapeDataString(orgId)}/projects")!;
    public Task<JsonNode> ListEnvironmentsAsync(string projectId) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/environments")!;
    public Task<JsonNode> ListSecretsAsync(string projectId, string environmentId) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/secrets?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> GetSecretAsync(string projectId, string environmentId, string key) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> ListSecretVersionsAsync(string projectId, string environmentId, string key) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}/versions?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> RestoreSecretAsync(string projectId, string environmentId, string key, int version) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}/restore", new { environment_id = environmentId, version })!;
    public Task<JsonNode> ListFoldersAsync(string projectId, string environmentId) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/folders?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> CreateFolderAsync(string projectId, string environmentId, string name, string path) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/folders", new { environment_id = environmentId, name, path })!;
    public Task<JsonNode> DeleteFolderAsync(string projectId, string folderId) => RequestAsync(HttpMethod.Delete, $"/projects/{Uri.EscapeDataString(projectId)}/folders/{Uri.EscapeDataString(folderId)}")!;
    public Task<JsonNode> ListImportsAsync(string projectId, string environmentId) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/imports?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> CreateImportAsync(string projectId, string environmentId, string sourceEnvironmentId, int position = 0) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/imports", new { environment_id = environmentId, source_environment_id = sourceEnvironmentId, position })!;
    public Task<JsonNode> DeleteImportAsync(string projectId, string importId) => RequestAsync(HttpMethod.Delete, $"/projects/{Uri.EscapeDataString(projectId)}/imports/{Uri.EscapeDataString(importId)}")!;
    public Task<JsonNode> ListTagsAsync(string projectId) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/tags")!;
    public Task<JsonNode> CreateTagAsync(string projectId, string name, string color = "#888888") => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/tags", new { name, color })!;
    public Task<JsonNode> DeleteTagAsync(string projectId, string tagId) => RequestAsync(HttpMethod.Delete, $"/projects/{Uri.EscapeDataString(projectId)}/tags/{Uri.EscapeDataString(tagId)}")!;
    public Task<JsonNode> ListSecretTagsAsync(string projectId, string environmentId, string key) => RequestAsync(HttpMethod.Get, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}/tags?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> TagSecretAsync(string projectId, string environmentId, string key, string tagId) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}/tags", new { environment_id = environmentId, tag_id = tagId })!;
    public Task<JsonNode> UntagSecretAsync(string projectId, string environmentId, string key, string tagId) => RequestAsync(HttpMethod.Delete, $"/projects/{Uri.EscapeDataString(projectId)}/secrets/{Uri.EscapeDataString(key)}/tags/{Uri.EscapeDataString(tagId)}?environment_id={Uri.EscapeDataString(environmentId)}")!;
    public Task<JsonNode> CreateOrgAsync(object body) => RequestAsync(HttpMethod.Post, "/orgs", body)!;
    public Task<JsonNode> CreateProjectAsync(object body) => RequestAsync(HttpMethod.Post, "/projects", body)!;
    public Task<JsonNode> CreateEnvironmentAsync(string projectId, object body) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/environments", body)!;
    public Task<JsonNode> CreateSecretAsync(string projectId, object body) => RequestAsync(HttpMethod.Post, $"/projects/{Uri.EscapeDataString(projectId)}/secrets", body)!;
    public Task<JsonNode> CreatePatAsync(object body) => RequestAsync(HttpMethod.Post, "/auth/pat", body)!;
}
