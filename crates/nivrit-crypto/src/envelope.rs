use serde::{Deserialize, Serialize};

/// An encapsulated project key, ready to be stored for a recipient.
///
/// Fields for the hybrid `X25519 + ML-KEM-768` suite:
/// - `encapsulated_key` holds the ephemeral X25519 public key.
/// - `ml_kem_ciphertext` holds the ML-KEM-768 ciphertext.
/// - `nonce` and `ciphertext` hold the AES-256-GCM payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncapsulatedProjectKey {
    pub suite: String,
    #[serde(with = "base64vec")]
    pub encapsulated_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "base64vec")]
    pub ml_kem_ciphertext: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "base64vec")]
    pub nonce: Vec<u8>,
    #[serde(with = "base64vec")]
    pub ciphertext: Vec<u8>,
}

mod base64vec {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
