package com.nivrit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class NivritSession {
    private final NivritClient client;
    private final HelperCrypto crypto;
    private final ObjectMapper mapper = new ObjectMapper();
    private JsonNode user;
    private String privateKey;
    private final Map<String, String> projectKeys = new HashMap<>();

    public NivritSession(String baseUrl, String token, HelperCrypto crypto) {
        this.client = new NivritClient(baseUrl, token);
        this.crypto = crypto;
    }

    public void authenticate(String password) throws IOException, InterruptedException {
        this.user = client.getMe();
        this.privateKey = crypto.decryptPrivateKey(
                user.get("encrypted_private_key").asText(),
                user.get("private_key_nonce").asText(),
                password);
    }

    public NivritClient getClient() { return client; }
    public JsonNode getUser() { return user; }

    public String getProjectKey(JsonNode membership) throws IOException {
        String pid = membership.get("project_id").asText();
        if (projectKeys.containsKey(pid)) return projectKeys.get(pid);
        String key = crypto.decapsulateProjectKey(
                membership.get("encrypted_project_key").asText(),
                privateKey);
        projectKeys.put(pid, key);
        return key;
    }

    public JsonNode listSecrets(String projectId, String environmentId) throws IOException, InterruptedException {
        JsonNode secrets = client.listSecrets(projectId, environmentId);
        JsonNode membership = null;
        for (JsonNode m : client.listMyProjects()) {
            if (m.get("project_id").asText().equals(projectId)) { membership = m; break; }
        }
        if (membership == null) throw new IOException("No membership for project " + projectId);
        String projectKey = getProjectKey(membership);

        for (JsonNode s : secrets) {
            String value = crypto.decryptValue(
                    s.get("encrypted_value").asText(),
                    s.get("nonce").asText(),
                    projectKey);
            ((ObjectNode) s).put("value", value);
        }
        return secrets;
    }
}
