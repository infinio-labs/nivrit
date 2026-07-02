use nivrit_core::{NivritError, Result};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::suite::{CryptoSuite, EncryptedValue};

/// Convenience wrapper: AES-256-GCM encryption.
/// Prefer `CryptoSuite::encrypt` directly when you need crypto-agility.
pub fn encrypt_value(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedValue> {
    CryptoSuite::Aes256GcmV1.encrypt(plaintext, key)
}

/// Convenience wrapper: AES-256-GCM decryption.
pub fn decrypt_value(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    CryptoSuite::Aes256GcmV1.decrypt(ciphertext, nonce, key)
}

pub fn derive_shared_key(private_key: &StaticSecret, public_key: &PublicKey) -> [u8; 32] {
    let shared = private_key.diffie_hellman(public_key);
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.finalize().into()
}

pub fn wrap_key(key: &[u8; 32], wrapping_key: &[u8; 32]) -> Result<EncryptedValue> {
    CryptoSuite::Aes256GcmV1.encrypt(key, wrapping_key)
}

pub fn unwrap_key(wrapped: &EncryptedValue, wrapping_key: &[u8; 32]) -> Result<[u8; 32]> {
    if wrapped.suite != CryptoSuite::Aes256GcmV1 {
        return Err(NivritError::Crypto(
            "key wrap only supports aes256gcm-v1".into(),
        ));
    }
    let bytes = wrapped.decrypt_with_key(wrapping_key)?;
    bytes
        .try_into()
        .map_err(|_| NivritError::Crypto("unwrapped key has wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = random_bytes::<32>();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let encrypted = encrypt_value(plaintext, &key).expect("encryption should succeed");
        assert_eq!(encrypted.nonce.len(), 12);
        assert_eq!(encrypted.suite, CryptoSuite::Aes256GcmV1);
        let decrypted = decrypt_value(&encrypted.ciphertext, &encrypted.nonce, &key)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let key = random_bytes::<32>();
        let wrong_key = random_bytes::<32>();
        let plaintext = b"secret message";
        let encrypted = encrypt_value(plaintext, &key).unwrap();
        assert!(decrypt_value(&encrypted.ciphertext, &encrypted.nonce, &wrong_key).is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let key = random_bytes::<32>();
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let encrypted = encrypt_value(b"x", &key).unwrap();
            let nonce = encrypted.nonce.clone();
            assert!(
                nonces.insert(nonce),
                "AES-GCM nonce must never repeat for the same key"
            );
        }
        assert_eq!(nonces.len(), 100);
    }

    #[test]
    fn key_wrap_roundtrip() {
        let kek = random_bytes::<32>();
        let dek = random_bytes::<32>();
        let wrapped = wrap_key(&dek, &kek).unwrap();
        let unwrapped = unwrap_key(&wrapped, &kek).unwrap();
        assert_eq!(dek, unwrapped);
    }
}
