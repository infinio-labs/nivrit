use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use nivrit_core::{NivritError, Result};
use serde::{Deserialize, Serialize};

/// Identifier for a supported authenticated-encryption scheme.
///
/// Storing the identifier alongside ciphertext is what makes Nivrit
/// "crypto-agile": old data can be decrypted while new data is encrypted
/// with an updated algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSuite {
    /// AES-256-GCM with a 96-bit random nonce.
    Aes256GcmV1,
    /// ChaCha20-Poly1305 with a 96-bit random nonce.
    ChaCha20Poly1305V1,
}

impl CryptoSuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoSuite::Aes256GcmV1 => "aes256gcm-v1",
            CryptoSuite::ChaCha20Poly1305V1 => "chacha20poly1305-v1",
        }
    }

    pub fn nonce_len(&self) -> usize {
        12
    }

    /// Encrypt `plaintext` under `key` using this suite.
    pub fn encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedValue> {
        let nonce = crate::keys::random_bytes::<12>();
        let ciphertext = match self {
            CryptoSuite::Aes256GcmV1 => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
                let nonce = AesNonce::from_slice(&nonce);
                cipher.encrypt(nonce, plaintext)
            }
            CryptoSuite::ChaCha20Poly1305V1 => {
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
                let nonce = ChaChaNonce::from_slice(&nonce);
                cipher.encrypt(nonce, plaintext)
            }
        }
        .map_err(|e| NivritError::Crypto(e.to_string()))?;

        Ok(EncryptedValue {
            suite: *self,
            ciphertext,
            nonce: nonce.to_vec(),
        })
    }

    /// Decrypt `ciphertext` using `nonce` and `key` for this suite.
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        match self {
            CryptoSuite::Aes256GcmV1 => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
                let nonce = AesNonce::from_slice(nonce);
                cipher.decrypt(nonce, ciphertext)
            }
            CryptoSuite::ChaCha20Poly1305V1 => {
                let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
                let nonce = ChaChaNonce::from_slice(nonce);
                cipher.decrypt(nonce, ciphertext)
            }
        }
        .map_err(|e| NivritError::Crypto(e.to_string()))
    }
}

impl std::str::FromStr for CryptoSuite {
    type Err = NivritError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "aes256gcm-v1" => Ok(CryptoSuite::Aes256GcmV1),
            "chacha20poly1305-v1" => Ok(CryptoSuite::ChaCha20Poly1305V1),
            _ => Err(NivritError::Crypto(format!(
                "unsupported crypto suite: {s}"
            ))),
        }
    }
}

/// A generic encrypted payload that carries its algorithm identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    pub suite: CryptoSuite,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptedValue {
    /// Convenience for callers that only have the string identifier.
    pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        self.suite.decrypt(&self.ciphertext, &self.nonce, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    #[test]
    fn aes256_gcm_roundtrip() {
        let key = random_bytes::<32>();
        let plaintext = b"hello aes";
        let enc = CryptoSuite::Aes256GcmV1.encrypt(plaintext, &key).unwrap();
        let dec = enc.decrypt_with_key(&key).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn chacha20_poly1305_roundtrip() {
        let key = random_bytes::<32>();
        let plaintext = b"hello chacha";
        let enc = CryptoSuite::ChaCha20Poly1305V1
            .encrypt(plaintext, &key)
            .unwrap();
        let dec = enc.decrypt_with_key(&key).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn wrong_suite_fails() {
        let key = random_bytes::<32>();
        let plaintext = b"secret";
        let enc = CryptoSuite::Aes256GcmV1.encrypt(plaintext, &key).unwrap();
        let wrong = CryptoSuite::ChaCha20Poly1305V1
            .decrypt(&enc.ciphertext, &enc.nonce, &key)
            .unwrap_err();
        assert!(matches!(wrong, NivritError::Crypto(_)));
    }

    #[test]
    fn suite_as_str_roundtrip() {
        assert_eq!(CryptoSuite::Aes256GcmV1.as_str(), "aes256gcm-v1");
        assert_eq!(
            CryptoSuite::ChaCha20Poly1305V1.as_str(),
            "chacha20poly1305-v1"
        );
        assert_eq!(
            "aes256gcm-v1".parse::<CryptoSuite>().unwrap(),
            CryptoSuite::Aes256GcmV1
        );
        assert_eq!(
            "chacha20poly1305-v1".parse::<CryptoSuite>().unwrap(),
            CryptoSuite::ChaCha20Poly1305V1
        );
    }

    #[test]
    fn unsupported_suite_errors() {
        let err = "des-cbc-v1".parse::<CryptoSuite>().unwrap_err();
        assert!(matches!(err, NivritError::Crypto(_)));
    }

    #[test]
    fn encrypted_value_serializes_and_deserializes() {
        let value = EncryptedValue {
            suite: CryptoSuite::Aes256GcmV1,
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let json = serde_json::to_string(&value).unwrap();
        let decoded: EncryptedValue = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.suite, value.suite);
        assert_eq!(decoded.ciphertext, value.ciphertext);
        assert_eq!(decoded.nonce, value.nonce);
    }
}
