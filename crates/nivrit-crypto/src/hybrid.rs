use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    MlKem768,
};
use nivrit_core::{NivritError, Result};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::envelope::EncapsulatedProjectKey;
use crate::suite::CryptoSuite;

/// Identifier for the X25519 + ML-KEM-768 hybrid project-key suite.
pub const HYBRID_SUITE_ID: &str = "hybrid_x25519_ml_kem_768_aes256gcm_v1";

const HYBRID_INFO: &[u8] = b"nivrit-hybrid-project-key-v1";
const HYBRID_KEY_TAG: u8 = 0x02;

const X25519_SECRET_LEN: usize = 32;
const X25519_PUBLIC_LEN: usize = 32;
const ML_KEM_SEED_LEN: usize = 64;
const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const HYBRID_PUBLIC_KEY_LEN: usize = 1 + X25519_PUBLIC_LEN + ML_KEM_PUBLIC_LEN;

/// A user key pair that combines an X25519 static DH key with an ML-KEM-768
/// KEM key. The resulting public key is safe against both classical and
/// post-quantum adversaries.
#[derive(Clone)]
pub struct HybridUserKeyPair {
    pub x25519_private: X25519StaticSecret,
    pub x25519_public: X25519PublicKey,
    pub ml_kem_seed: [u8; ML_KEM_SEED_LEN],
    pub ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
}

impl std::fmt::Debug for HybridUserKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridUserKeyPair")
            .field("x25519_public", &self.x25519_public)
            .field("ml_kem_public_len", &self.ml_kem_public.len())
            .finish_non_exhaustive()
    }
}

impl HybridUserKeyPair {
    /// Generate a new hybrid user key pair using the OS RNG.
    pub fn generate() -> Self {
        let x25519_private = X25519StaticSecret::random();
        let x25519_public = X25519PublicKey::from(&x25519_private);

        let (dk, ek) = MlKem768::generate_keypair();
        let ml_kem_seed: [u8; ML_KEM_SEED_LEN] = dk.to_bytes().into();
        let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] = ek.to_bytes().into();

        Self {
            x25519_private,
            x25519_public,
            ml_kem_seed,
            ml_kem_public,
        }
    }

    /// Serialize the public key to a wire format that can be stored in the
    /// `users.public_key` column.
    ///
    /// Format: `[tag:1][x25519_public:32][ml_kem_public:1184]`.
    pub fn serialize_public_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + X25519_PUBLIC_LEN + ML_KEM_PUBLIC_LEN);
        out.push(HYBRID_KEY_TAG);
        out.extend_from_slice(self.x25519_public.as_bytes());
        out.extend_from_slice(&self.ml_kem_public);
        out
    }

    /// Serialize the private key to a compact plaintext form that is later
    /// encrypted under the user's password.
    ///
    /// Format: `[tag:1][x25519_secret:32][ml_kem_seed:64]`.
    pub fn serialize_private_key(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN);
        out.push(HYBRID_KEY_TAG);
        out.extend_from_slice(self.x25519_private.as_bytes());
        out.extend_from_slice(&self.ml_kem_seed);
        out
    }

    /// Recover a hybrid key pair from serialized private-key bytes.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN {
            return Err(NivritError::Crypto(
                "invalid hybrid private key length".into(),
            ));
        }
        if bytes[0] != HYBRID_KEY_TAG {
            return Err(NivritError::Crypto("invalid hybrid private key tag".into()));
        }

        let x25519_secret: [u8; X25519_SECRET_LEN] = bytes[1..1 + X25519_SECRET_LEN]
            .try_into()
            .map_err(|_| NivritError::Crypto("x25519 secret has wrong length".into()))?;
        let x25519_private = X25519StaticSecret::from(x25519_secret);
        let x25519_public = X25519PublicKey::from(&x25519_private);

        let ml_kem_seed: [u8; ML_KEM_SEED_LEN] = bytes
            [1 + X25519_SECRET_LEN..1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN]
            .try_into()
            .map_err(|_| NivritError::Crypto("ml-kem seed has wrong length".into()))?;

        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem_seed.into());
        let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] = dk.encapsulation_key().to_bytes().into();

        Ok(Self {
            x25519_private,
            x25519_public,
            ml_kem_seed,
            ml_kem_public,
        })
    }
}

fn parse_hybrid_public_key(
    public_key: &[u8],
) -> Result<(X25519PublicKey, ml_kem::EncapsulationKey<MlKem768>)> {
    if public_key.len() != HYBRID_PUBLIC_KEY_LEN {
        return Err(NivritError::Crypto(format!(
            "invalid hybrid public key length: expected {}, got {}",
            HYBRID_PUBLIC_KEY_LEN,
            public_key.len()
        )));
    }
    if public_key[0] != HYBRID_KEY_TAG {
        return Err(NivritError::Crypto("unknown hybrid public key tag".into()));
    }

    let x25519_bytes: [u8; X25519_PUBLIC_LEN] = public_key[1..1 + X25519_PUBLIC_LEN]
        .try_into()
        .map_err(|_| NivritError::Crypto("x25519 public key has wrong length".into()))?;
    let x25519_public = X25519PublicKey::from(x25519_bytes);

    let ml_kem_bytes: [u8; ML_KEM_PUBLIC_LEN] = public_key[1 + X25519_PUBLIC_LEN..]
        .try_into()
        .map_err(|_| NivritError::Crypto("ml-kem public key has wrong length".into()))?;
    let ml_kem_public = ml_kem::EncapsulationKey::<MlKem768>::new(&ml_kem_bytes.into())
        .map_err(|_| NivritError::Crypto("invalid ml-kem public key".into()))?;

    Ok((x25519_public, ml_kem_public))
}

fn parse_hybrid_private_key(
    private_key: &[u8],
) -> Result<(X25519StaticSecret, ml_kem::DecapsulationKey<MlKem768>)> {
    if private_key.len() != 1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN {
        return Err(NivritError::Crypto(
            "invalid hybrid private key length".into(),
        ));
    }
    if private_key[0] != HYBRID_KEY_TAG {
        return Err(NivritError::Crypto("invalid hybrid private key tag".into()));
    }

    let x25519_secret: [u8; X25519_SECRET_LEN] =
        private_key[1..1 + X25519_SECRET_LEN]
            .try_into()
            .map_err(|_| NivritError::Crypto("x25519 secret has wrong length".into()))?;
    let x25519_private = X25519StaticSecret::from(x25519_secret);

    let ml_kem_seed: [u8; ML_KEM_SEED_LEN] = private_key
        [1 + X25519_SECRET_LEN..1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN]
        .try_into()
        .map_err(|_| NivritError::Crypto("ml-kem seed has wrong length".into()))?;
    let ml_kem_private = ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem_seed.into());

    Ok((x25519_private, ml_kem_private))
}

/// Encrypt a 32-byte project key to a recipient's hybrid public key.
pub fn encapsulate_project_key_hybrid(
    project_key: &[u8; 32],
    recipient_public_key: &[u8],
) -> Result<EncapsulatedProjectKey> {
    let (recipient_x25519, recipient_ml_kem) = parse_hybrid_public_key(recipient_public_key)?;

    // X25519 ephemeral DH.
    let ephemeral_private = X25519StaticSecret::random();
    let ephemeral_public = X25519PublicKey::from(&ephemeral_private);
    let x25519_shared = ephemeral_private.diffie_hellman(&recipient_x25519);

    // ML-KEM encapsulation.
    let (ml_kem_ciphertext, ml_kem_shared) = recipient_ml_kem.encapsulate();

    // Combine the two shared secrets with HKDF-SHA256.
    let mut salt = Vec::with_capacity(X25519_PUBLIC_LEN + ML_KEM_CIPHERTEXT_LEN);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(ml_kem_ciphertext.as_slice());

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(ml_kem_shared.as_slice());

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(HYBRID_INFO, &mut okm)
        .map_err(|e| NivritError::Crypto(format!("hkdf expand failed: {e:?}")))?;

    // AEAD-encrypt the project key under the derived symmetric key.
    let encrypted = CryptoSuite::Aes256GcmV1.encrypt(project_key, &okm)?;

    Ok(EncapsulatedProjectKey {
        suite: HYBRID_SUITE_ID.into(),
        encapsulated_key: ephemeral_public.as_bytes().to_vec(),
        ml_kem_ciphertext: ml_kem_ciphertext.as_slice().to_vec(),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

/// Re-encrypt an encapsulated project key from one hybrid recipient to another.
///
/// This is the primitive used by the re-encryption worker: the old recipient
/// decrypts the key they hold, and the result is immediately encapsulated for
/// the new recipient.
pub fn reencrypt_project_key_hybrid(
    encapsulated: &EncapsulatedProjectKey,
    old_recipient_private_key: &[u8],
    new_recipient_public_key: &[u8],
) -> Result<EncapsulatedProjectKey> {
    let project_key = decapsulate_project_key_hybrid(encapsulated, old_recipient_private_key)?;
    encapsulate_project_key_hybrid(&project_key, new_recipient_public_key)
}

/// Decrypt a hybrid-encapsulated project key using the recipient's hybrid
/// private key.
pub fn decapsulate_project_key_hybrid(
    encapsulated: &EncapsulatedProjectKey,
    recipient_private_key: &[u8],
) -> Result<[u8; 32]> {
    if encapsulated.suite != HYBRID_SUITE_ID {
        return Err(NivritError::Crypto(format!(
            "unsupported hybrid suite: {}",
            encapsulated.suite
        )));
    }

    let (x25519_private, ml_kem_private) = parse_hybrid_private_key(recipient_private_key)?;

    if encapsulated.encapsulated_key.len() != X25519_PUBLIC_LEN {
        return Err(NivritError::Crypto(
            "invalid x25519 ephemeral public key length".into(),
        ));
    }
    let ephemeral_public: [u8; X25519_PUBLIC_LEN] = encapsulated
        .encapsulated_key
        .as_slice()
        .try_into()
        .map_err(|_| NivritError::Crypto("x25519 ephemeral public key has wrong length".into()))?;
    let ephemeral_public = X25519PublicKey::from(ephemeral_public);
    let x25519_shared = x25519_private.diffie_hellman(&ephemeral_public);

    if encapsulated.ml_kem_ciphertext.len() != ML_KEM_CIPHERTEXT_LEN {
        return Err(NivritError::Crypto(
            "invalid ml-kem ciphertext length".into(),
        ));
    }
    let ml_kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_LEN] = encapsulated
        .ml_kem_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| NivritError::Crypto("ml-kem ciphertext has wrong length".into()))?;
    let ml_kem_ciphertext: ml_kem::Ciphertext<MlKem768> = ml_kem_ciphertext.into();
    let ml_kem_shared = ml_kem_private.decapsulate(&ml_kem_ciphertext);

    let mut salt = Vec::with_capacity(X25519_PUBLIC_LEN + ML_KEM_CIPHERTEXT_LEN);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(ml_kem_ciphertext.as_slice());

    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(x25519_shared.as_bytes());
    ikm.extend_from_slice(ml_kem_shared.as_slice());

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(HYBRID_INFO, &mut okm)
        .map_err(|e| NivritError::Crypto(format!("hkdf expand failed: {e:?}")))?;

    let plaintext =
        CryptoSuite::Aes256GcmV1.decrypt(&encapsulated.ciphertext, &encapsulated.nonce, &okm)?;

    plaintext
        .try_into()
        .map_err(|_| NivritError::Crypto("decapsulated project key has wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    #[test]
    fn hybrid_keypair_serialization_roundtrip() {
        let kp = HybridUserKeyPair::generate();
        let public = kp.serialize_public_key();
        let private = kp.serialize_private_key();

        assert_eq!(public.len(), 1 + X25519_PUBLIC_LEN + ML_KEM_PUBLIC_LEN);
        assert_eq!(private.len(), 1 + X25519_SECRET_LEN + ML_KEM_SEED_LEN);
        assert_eq!(public[0], HYBRID_KEY_TAG);
        assert_eq!(private[0], HYBRID_KEY_TAG);

        let recovered = HybridUserKeyPair::from_private_key_bytes(&private).unwrap();
        assert_eq!(
            recovered.x25519_public.as_bytes(),
            kp.x25519_public.as_bytes()
        );
        assert_eq!(recovered.ml_kem_public, kp.ml_kem_public);
    }

    #[test]
    fn hybrid_project_key_roundtrip() {
        let project_key = random_bytes::<32>();

        let recipient = HybridUserKeyPair::generate();
        let recipient_public = recipient.serialize_public_key();
        let recipient_private = recipient.serialize_private_key();

        let encapsulated = encapsulate_project_key_hybrid(&project_key, &recipient_public).unwrap();
        assert_eq!(encapsulated.suite, HYBRID_SUITE_ID);

        let decapsulated =
            decapsulate_project_key_hybrid(&encapsulated, &recipient_private).unwrap();
        assert_eq!(project_key, decapsulated);
    }

    #[test]
    fn hybrid_wrong_private_key_fails() {
        let project_key = random_bytes::<32>();

        let recipient = HybridUserKeyPair::generate();
        let recipient_public = recipient.serialize_public_key();
        let wrong = HybridUserKeyPair::generate();
        let wrong_private = wrong.serialize_private_key();

        let encapsulated = encapsulate_project_key_hybrid(&project_key, &recipient_public).unwrap();
        assert!(decapsulate_project_key_hybrid(&encapsulated, &wrong_private).is_err());
    }

    #[test]
    fn malformed_hybrid_public_key_is_rejected() {
        let project_key = random_bytes::<32>();
        let mut pk = HybridUserKeyPair::generate().serialize_public_key();
        // Truncate the public key to an invalid length.
        pk.truncate(pk.len() - 1);
        assert!(encapsulate_project_key_hybrid(&project_key, &pk).is_err());
    }

    #[test]
    fn bad_hybrid_public_key_tag_is_rejected() {
        let mut pk = HybridUserKeyPair::generate().serialize_public_key();
        pk[0] = 0xff;
        assert!(encapsulate_project_key_hybrid(&random_bytes::<32>(), &pk).is_err());
    }

    #[test]
    fn hybrid_reencrypt_project_key() {
        let project_key = random_bytes::<32>();

        let old = HybridUserKeyPair::generate();
        let old_public = old.serialize_public_key();
        let old_private = old.serialize_private_key();

        let new = HybridUserKeyPair::generate();
        let new_public = new.serialize_public_key();
        let new_private = new.serialize_private_key();

        let old_enc = encapsulate_project_key_hybrid(&project_key, &old_public).unwrap();
        let new_enc = reencrypt_project_key_hybrid(&old_enc, &old_private, &new_public).unwrap();

        let recovered = decapsulate_project_key_hybrid(&new_enc, &new_private).unwrap();
        assert_eq!(project_key, recovered);
    }

    #[test]
    fn from_private_key_bytes_rejects_wrong_lengths() {
        assert!(HybridUserKeyPair::from_private_key_bytes(&[0u8; 32]).is_err());
        assert!(HybridUserKeyPair::from_private_key_bytes(&[0u8; 97]).is_err());
    }
}
