package com.nivrit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Locale;

public class HelperCrypto {
    private final String helperPath;
    private final ObjectMapper mapper = new ObjectMapper();

    public HelperCrypto() {
        this.helperPath = findHelper();
    }

    public HelperCrypto(String helperPath) {
        this.helperPath = helperPath;
    }

    private static String findHelper() {
        String env = System.getenv("NIVRIT_CRYPTO_HELPER");
        if (env != null && !env.isEmpty()) return env;
        try {
            String extracted = extractFromResources();
            if (extracted != null) return extracted;
        } catch (Exception ignored) {
            // fall through to dev build
        }
        Path here = Paths.get("").toAbsolutePath();
        return here.resolve(Paths.get("..", "..", "..", "target", "release", "nivrit-crypto-helper")).toString();
    }

    // Extracts the platform helper bundled as a JAR resource at
    // /native/<os>-<arch>/nivrit-crypto-helper[.exe] (see build-resources.sh) to a
    // content-addressed temp path. The sha pins the binary to its bytes, so a
    // version bump never resolves a stale helper. Returns null if not bundled.
    private static String extractFromResources() throws IOException {
        boolean win = osName().equals("windows");
        String exe = win ? "nivrit-crypto-helper.exe" : "nivrit-crypto-helper";
        String resource = "/native/" + osName() + "-" + archName() + "/" + exe;
        byte[] bytes;
        try (InputStream in = HelperCrypto.class.getResourceAsStream(resource)) {
            if (in == null) return null;
            bytes = in.readAllBytes();
        }
        Path dir = Paths.get(System.getProperty("java.io.tmpdir"), "nivrit-crypto-helper", sha256(bytes));
        Files.createDirectories(dir);
        Path target = dir.resolve(exe);
        if (!Files.exists(target)) {
            Path tmp = Files.createTempFile(dir, "helper", ".tmp");
            Files.write(tmp, bytes);
            tmp.toFile().setExecutable(true, false);
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        return target.toString();
    }

    private static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        return "linux";
    }

    private static String archName() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("aarch64") || arch.equals("arm64")) return "arm64";
        return "x86_64";
    }

    private static String sha256(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", digest[i]));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private JsonNode call(ObjectNode req) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(helperPath);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        try (OutputStream os = proc.getOutputStream()) {
            os.write(mapper.writeValueAsBytes(req));
        }
        InputStream is = proc.getInputStream();
        String output = new String(is.readAllBytes());
        try {
            proc.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("crypto helper interrupted", e);
        }
        JsonNode resp = mapper.readTree(output.trim());
        if (!resp.get("ok").asBoolean()) {
            throw new IOException("crypto helper error: " + resp.get("error").asText());
        }
        return resp.get("result");
    }

    public String hybridSuiteId() throws IOException {
        ObjectNode req = mapper.createObjectNode().put("op", "hybrid_suite_id");
        return call(req).asText();
    }

    public ObjectNode generateKeypair(String password) throws IOException {
        ObjectNode req = mapper.createObjectNode().put("op", "generate_keypair").put("password", password);
        return (ObjectNode) call(req);
    }

    public String decryptPrivateKey(String encryptedPrivateKey, String nonce, String password) throws IOException {
        ObjectNode req = mapper.createObjectNode()
                .put("op", "decrypt_private_key")
                .put("encrypted_private_key", encryptedPrivateKey)
                .put("nonce", nonce)
                .put("password", password);
        return call(req).get("private_key").asText();
    }

    public String decapsulateProjectKey(String encryptedProjectKey, String privateKey) throws IOException {
        ObjectNode req = mapper.createObjectNode()
                .put("op", "decapsulate_project_key")
                .put("encrypted_project_key", encryptedProjectKey)
                .put("private_key", privateKey);
        return call(req).get("project_key").asText();
    }

    public ObjectNode encryptValue(String plaintext, String key) throws IOException {
        ObjectNode req = mapper.createObjectNode()
                .put("op", "encrypt_value")
                .put("plaintext", plaintext)
                .put("key", key);
        return (ObjectNode) call(req);
    }

    public String decryptValue(String ciphertext, String nonce, String key) throws IOException {
        ObjectNode req = mapper.createObjectNode()
                .put("op", "decrypt_value")
                .put("ciphertext", ciphertext)
                .put("nonce", nonce)
                .put("key", key);
        return call(req).get("plaintext").asText();
    }

    public ObjectNode encapsulateProjectKey(String projectKey, String recipientPublicKey) throws IOException {
        ObjectNode req = mapper.createObjectNode()
                .put("op", "encapsulate_project_key")
                .put("project_key", projectKey)
                .put("recipient_public_key", recipientPublicKey);
        return (ObjectNode) call(req);
    }
}
