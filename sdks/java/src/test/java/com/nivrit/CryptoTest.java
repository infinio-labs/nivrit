package com.nivrit;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

// Hermetic crypto round-trips through the nivrit-crypto-helper binary; no API
// required. Set NIVRIT_CRYPTO_HELPER or build the helper at target/release.
public class CryptoTest {
    private final HelperCrypto c = new HelperCrypto();

    private static String randKeyB64() {
        byte[] b = new byte[32];
        new SecureRandom().nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    @Test
    void hybridSuiteId() throws Exception {
        assertEquals("hybrid_x25519_ml_kem_768_aes256gcm_v1", c.hybridSuiteId());
    }

    @Test
    void valueRoundTrip() throws Exception {
        String key = randKeyB64();
        ObjectNode enc = c.encryptValue("hello-java", key);
        assertEquals(
                "hello-java",
                c.decryptValue(enc.get("ciphertext").asText(), enc.get("nonce").asText(), key));
    }

    @Test
    void keypairAndProjectKey() throws Exception {
        String pw = "correct horse battery staple";
        ObjectNode kp = c.generateKeypair(pw);
        String priv = c.decryptPrivateKey(
                kp.get("encrypted_private_key").asText(),
                kp.get("private_key_nonce").asText(),
                pw);

        String projectKey = randKeyB64();
        ObjectNode enc = c.encapsulateProjectKey(projectKey, kp.get("public_key").asText());
        String blob = Base64.getEncoder()
                .encodeToString(enc.toString().getBytes(StandardCharsets.UTF_8));

        assertEquals(projectKey, c.decapsulateProjectKey(blob, priv));
    }
}
