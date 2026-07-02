package com.nivrit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class NivritClient {
    private final String baseUrl;
    private final String token;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    public NivritClient(String baseUrl, String token) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.token = token;
    }

    private JsonNode request(String method, String path, JsonNode body) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json");
        if (body != null) {
            builder.method(method, HttpRequest.BodyPublishers.ofString(body.toString()));
        } else if (!method.equals("GET")) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            builder.GET();
        }
        HttpResponse<String> resp = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IOException("Nivrit API error " + resp.statusCode() + ": " + resp.body());
        }
        String text = resp.body();
        return text.isEmpty() ? null : mapper.readTree(text);
    }

    public JsonNode getMe() throws IOException, InterruptedException { return request("GET", "/users/me", null); }
    public JsonNode listOrgs() throws IOException, InterruptedException { return request("GET", "/users/me/orgs", null); }
    public JsonNode listMyProjects() throws IOException, InterruptedException { return request("GET", "/users/me/projects", null); }
    public JsonNode listOrgProjects(String orgId) throws IOException, InterruptedException { return request("GET", "/orgs/" + enc(orgId) + "/projects", null); }
    public JsonNode listEnvironments(String projectId) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/environments", null); }
    public JsonNode listSecrets(String projectId, String environmentId) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/secrets?environment_id=" + enc(environmentId), null); }
    public JsonNode getSecret(String projectId, String environmentId, String key) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "?environment_id=" + enc(environmentId), null); }
    public JsonNode listSecretVersions(String projectId, String environmentId, String key) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "/versions?environment_id=" + enc(environmentId), null); }
    public JsonNode restoreSecret(String projectId, String environmentId, String key, int version) throws IOException, InterruptedException {
        com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        body.put("environment_id", environmentId);
        body.put("version", version);
        return request("POST", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "/restore", body);
    }
    public JsonNode listFolders(String projectId, String environmentId) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/folders?environment_id=" + enc(environmentId), null); }
    public JsonNode createFolder(String projectId, String environmentId, String name, String path) throws IOException, InterruptedException {
        com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        body.put("environment_id", environmentId);
        body.put("name", name);
        body.put("path", path);
        return request("POST", "/projects/" + enc(projectId) + "/folders", body);
    }
    public JsonNode deleteFolder(String projectId, String folderId) throws IOException, InterruptedException { return request("DELETE", "/projects/" + enc(projectId) + "/folders/" + enc(folderId), null); }
    public JsonNode listImports(String projectId, String environmentId) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/imports?environment_id=" + enc(environmentId), null); }
    public JsonNode createImport(String projectId, String environmentId, String sourceEnvironmentId, int position) throws IOException, InterruptedException {
        com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        body.put("environment_id", environmentId);
        body.put("source_environment_id", sourceEnvironmentId);
        body.put("position", position);
        return request("POST", "/projects/" + enc(projectId) + "/imports", body);
    }
    public JsonNode deleteImport(String projectId, String importId) throws IOException, InterruptedException { return request("DELETE", "/projects/" + enc(projectId) + "/imports/" + enc(importId), null); }
    public JsonNode listTags(String projectId) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/tags", null); }
    public JsonNode createTag(String projectId, String name, String color) throws IOException, InterruptedException {
        com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        body.put("name", name);
        body.put("color", color);
        return request("POST", "/projects/" + enc(projectId) + "/tags", body);
    }
    public JsonNode deleteTag(String projectId, String tagId) throws IOException, InterruptedException { return request("DELETE", "/projects/" + enc(projectId) + "/tags/" + enc(tagId), null); }
    public JsonNode listSecretTags(String projectId, String environmentId, String key) throws IOException, InterruptedException { return request("GET", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "/tags?environment_id=" + enc(environmentId), null); }
    public JsonNode tagSecret(String projectId, String environmentId, String key, String tagId) throws IOException, InterruptedException {
        com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        body.put("environment_id", environmentId);
        body.put("tag_id", tagId);
        return request("POST", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "/tags", body);
    }
    public JsonNode untagSecret(String projectId, String environmentId, String key, String tagId) throws IOException, InterruptedException { return request("DELETE", "/projects/" + enc(projectId) + "/secrets/" + enc(key) + "/tags/" + enc(tagId) + "?environment_id=" + enc(environmentId), null); }
    public JsonNode createOrg(JsonNode body) throws IOException, InterruptedException { return request("POST", "/orgs", body); }
    public JsonNode createProject(JsonNode body) throws IOException, InterruptedException { return request("POST", "/projects", body); }
    public JsonNode createEnvironment(String projectId, JsonNode body) throws IOException, InterruptedException { return request("POST", "/projects/" + enc(projectId) + "/environments", body); }
    public JsonNode createSecret(String projectId, JsonNode body) throws IOException, InterruptedException { return request("POST", "/projects/" + enc(projectId) + "/secrets", body); }
    public JsonNode createPat(JsonNode body) throws IOException, InterruptedException { return request("POST", "/auth/pat", body); }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
