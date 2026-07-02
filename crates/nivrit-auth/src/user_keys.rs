use nivrit_core::Result;
use nivrit_crypto::suite::{CryptoSuite, EncryptedValue};

/// Encrypt a plaintext private key with a password-derived key.
/// Mirrors the client-side WASM/CLI format: a 16-byte random Argon2id salt is
/// prepended to the ciphertext, and the AES-GCM nonce is stored separately.
pub fn encrypt_private_key_with_password(
    private_key: &[u8],
    password: &str,
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let salt = nivrit_crypto::keys::random_bytes::<16>();
    let derived = nivrit_crypto::password::derive_key(password.as_bytes(), &salt);
    let encrypted = CryptoSuite::Aes256GcmV1.encrypt(private_key, &derived)?;
    let mut combined = salt.to_vec();
    combined.extend_from_slice(&encrypted.ciphertext);
    Ok((
        combined,
        encrypted.nonce,
        CryptoSuite::Aes256GcmV1.as_str().to_string(),
    ))
}

/// Decrypt a private key that was encrypted with a password-derived key.
pub fn decrypt_private_key_with_password(
    encrypted_private_key: &[u8],
    nonce: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    if encrypted_private_key.len() < 16 {
        return Err(nivrit_core::NivritError::Crypto(
            "invalid encrypted private key length".into(),
        ));
    }
    let salt = &encrypted_private_key[..16];
    let ciphertext = &encrypted_private_key[16..];
    let derived = nivrit_crypto::password::derive_key(password.as_bytes(), salt);
    CryptoSuite::Aes256GcmV1.decrypt(ciphertext, nonce, &derived)
}

/// Decrypt using an explicit EncryptedValue envelope.
pub fn decrypt_private_key_value(encrypted: &EncryptedValue, password: &str) -> Result<Vec<u8>> {
    decrypt_private_key_with_password(&encrypted.ciphertext, &encrypted.nonce, password)
}
