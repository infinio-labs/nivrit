use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_crypto::{
    decapsulate_project_key_hybrid, decrypt_value as crypto_decrypt_value,
    derive_key as argon2_derive_key, encapsulate_project_key_hybrid,
    encrypt_value as crypto_encrypt_value, EncapsulatedProjectKey, HybridUserKeyPair,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Install a panic hook that forwards Rust panics to `console.error`.
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

fn err(s: String) -> JsValue {
    js_sys::Error::new(&s).into()
}

fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, JsValue> {
    STANDARD
        .decode(s)
        .map_err(|e| err(format!("invalid base64: {e}")))
}

/// Result of generating a user keypair from a password.
#[derive(Serialize, Deserialize)]
pub struct GeneratedKeypair {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    pub private_key_algorithm: String,
}

/// Generate a hybrid `X25519 + ML-KEM-768` keypair and encrypt the private key
/// to `password` using Argon2id + AES-256-GCM.
#[wasm_bindgen]
pub fn generate_user_keypair(password: &str) -> Result<JsValue, JsValue> {
    let keypair = HybridUserKeyPair::generate();
    let private_key_plaintext = keypair.serialize_private_key();

    let salt = nivrit_crypto::random_bytes::<16>();
    let key = argon2_derive_key(password.as_bytes(), &salt);
    let encrypted = crypto_encrypt_value(&private_key_plaintext, &key)
        .map_err(|e| err(format!("failed to encrypt private key: {e}")))?;

    let mut combined = salt.to_vec();
    combined.extend_from_slice(&encrypted.ciphertext);

    Ok(serde_wasm_bindgen::to_value(&GeneratedKeypair {
        public_key: b64_encode(&keypair.serialize_public_key()),
        encrypted_private_key: b64_encode(&combined),
        private_key_nonce: b64_encode(&encrypted.nonce),
        private_key_algorithm: "aes256gcm-v1".into(),
    })?)
}

/// Result of decrypting a user's private key.
#[derive(Serialize, Deserialize)]
pub struct DecryptedPrivateKey {
    pub private_key: String,
}

/// Decrypt a private key that was produced by `generate_user_keypair`.
#[wasm_bindgen]
pub fn decrypt_private_key(
    encrypted_private_key_b64: &str,
    nonce_b64: &str,
    password: &str,
) -> Result<JsValue, JsValue> {
    let encrypted_private_key = b64_decode(encrypted_private_key_b64)?;
    if encrypted_private_key.len() < 16 {
        return Err(err("invalid encrypted private key length".into()));
    }
    let salt = &encrypted_private_key[..16];
    let ciphertext = &encrypted_private_key[16..];
    let nonce = b64_decode(nonce_b64)?;

    let key = argon2_derive_key(password.as_bytes(), salt);
    let plaintext = crypto_decrypt_value(ciphertext, &nonce, &key)
        .map_err(|e| err(format!("failed to decrypt private key: {e}")))?;

    Ok(serde_wasm_bindgen::to_value(&DecryptedPrivateKey {
        private_key: b64_encode(&plaintext),
    })?)
}

/// Encapsulate a 32-byte project key to a recipient's hybrid public key.
#[wasm_bindgen]
pub fn encapsulate_project_key(
    project_key_b64: &str,
    recipient_public_key_b64: &str,
) -> Result<JsValue, JsValue> {
    let project_key_bytes = b64_decode(project_key_b64)?;
    let project_key: [u8; 32] = project_key_bytes
        .try_into()
        .map_err(|_| err("project key must be 32 bytes".into()))?;
    let recipient_public_key = b64_decode(recipient_public_key_b64)?;

    let encapsulated = encapsulate_project_key_hybrid(&project_key, &recipient_public_key)
        .map_err(|e| err(format!("encapsulation failed: {e}")))?;

    Ok(serde_wasm_bindgen::to_value(&encapsulated)?)
}

/// Result of decapsulating a project key.
#[derive(Serialize, Deserialize)]
pub struct DecryptedProjectKey {
    pub project_key: String,
}

/// Decapsulate a project key using the recipient's plaintext hybrid private key.
#[wasm_bindgen]
pub fn decapsulate_project_key(
    encapsulated: JsValue,
    private_key_b64: &str,
) -> Result<JsValue, JsValue> {
    let encapsulated: EncapsulatedProjectKey = serde_wasm_bindgen::from_value(encapsulated)
        .map_err(|e| err(format!("invalid encapsulated project key: {e}")))?;
    let private_key = b64_decode(private_key_b64)?;

    let project_key = decapsulate_project_key_hybrid(&encapsulated, &private_key)
        .map_err(|e| err(format!("decapsulation failed: {e}")))?;

    Ok(serde_wasm_bindgen::to_value(&DecryptedProjectKey {
        project_key: b64_encode(&project_key),
    })?)
}

/// Result of AES-256-GCM encryption.
#[derive(Serialize, Deserialize)]
pub struct EncryptedValue {
    pub ciphertext: String,
    pub nonce: String,
}

/// Encrypt a UTF-8 string under a 32-byte AES-256-GCM key.
#[wasm_bindgen]
pub fn encrypt_value(plaintext: &str, key_b64: &str) -> Result<JsValue, JsValue> {
    let key_bytes = b64_decode(key_b64)?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| err("key must be 32 bytes".into()))?;

    let encrypted = crypto_encrypt_value(plaintext.as_bytes(), &key)
        .map_err(|e| err(format!("encryption failed: {e}")))?;

    Ok(serde_wasm_bindgen::to_value(&EncryptedValue {
        ciphertext: b64_encode(&encrypted.ciphertext),
        nonce: b64_encode(&encrypted.nonce),
    })?)
}

/// Result of AES-256-GCM decryption.
#[derive(Serialize, Deserialize)]
pub struct DecryptedValue {
    pub plaintext: String,
}

/// Decrypt a base64 ciphertext under a 32-byte AES-256-GCM key and nonce.
#[wasm_bindgen]
pub fn decrypt_value(
    ciphertext_b64: &str,
    nonce_b64: &str,
    key_b64: &str,
) -> Result<JsValue, JsValue> {
    let ciphertext = b64_decode(ciphertext_b64)?;
    let nonce = b64_decode(nonce_b64)?;
    let key_bytes = b64_decode(key_b64)?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| err("key must be 32 bytes".into()))?;

    let plaintext = crypto_decrypt_value(&ciphertext, &nonce, &key)
        .map_err(|e| err(format!("decryption failed: {e}")))?;
    let plaintext = String::from_utf8(plaintext)
        .map_err(|e| err(format!("plaintext is not valid utf-8: {e}")))?;

    Ok(serde_wasm_bindgen::to_value(&DecryptedValue { plaintext })?)
}

/// Return the suite identifier used for hybrid project-key encapsulation.
#[wasm_bindgen]
pub fn hybrid_suite_id() -> String {
    nivrit_crypto::HYBRID_SUITE_ID.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn generate_and_decrypt_private_key() {
        let password = "correct-horse-battery-staple";
        let generated = generate_user_keypair(password).unwrap();
        let generated: GeneratedKeypair = serde_wasm_bindgen::from_value(generated).unwrap();

        let decrypted = decrypt_private_key(
            &generated.encrypted_private_key,
            &generated.private_key_nonce,
            password,
        )
        .unwrap();
        let decrypted: DecryptedPrivateKey = serde_wasm_bindgen::from_value(decrypted).unwrap();

        assert!(!decrypted.private_key.is_empty());
    }

    #[wasm_bindgen_test]
    fn wrong_password_fails_to_decrypt_private_key() {
        let generated = generate_user_keypair("right-password").unwrap();
        let generated: GeneratedKeypair = serde_wasm_bindgen::from_value(generated).unwrap();
        assert!(decrypt_private_key(
            &generated.encrypted_private_key,
            &generated.private_key_nonce,
            "wrong-password"
        )
        .is_err());
    }

    #[wasm_bindgen_test]
    fn self_encapsulated_project_key_roundtrip() {
        let project_key = b64_encode(&nivrit_crypto::random_bytes::<32>());
        let keypair = generate_user_keypair("password").unwrap();
        let keypair: GeneratedKeypair = serde_wasm_bindgen::from_value(keypair).unwrap();

        let encapsulated = encapsulate_project_key(&project_key, &keypair.public_key).unwrap();
        let private_key_js = decrypt_private_key(
            &keypair.encrypted_private_key,
            &keypair.private_key_nonce,
            "password",
        )
        .unwrap();
        let private_key: DecryptedPrivateKey =
            serde_wasm_bindgen::from_value(private_key_js).unwrap();

        let recovered = decapsulate_project_key(encapsulated, &private_key.private_key).unwrap();
        let recovered: DecryptedProjectKey = serde_wasm_bindgen::from_value(recovered).unwrap();

        assert_eq!(recovered.project_key, project_key);
    }

    #[wasm_bindgen_test]
    fn aes_gcm_roundtrip() {
        let key = b64_encode(&nivrit_crypto::random_bytes::<32>());
        let encrypted = encrypt_value("hello wasm", &key).unwrap();
        let encrypted: EncryptedValue = serde_wasm_bindgen::from_value(encrypted).unwrap();
        let decrypted = decrypt_value(&encrypted.ciphertext, &encrypted.nonce, &key).unwrap();
        let decrypted: DecryptedValue = serde_wasm_bindgen::from_value(decrypted).unwrap();
        assert_eq!(decrypted.plaintext, "hello wasm");
    }
}
