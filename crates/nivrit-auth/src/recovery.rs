use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{
        rand_core::RngCore, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use nivrit_core::{NivritError, Result};

const RECOVERY_SALT: &[u8] = b"nivrit-recovery-v1";
const RECOVERY_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // omit 0/O/I/L

/// Generate a human-friendly recovery code, e.g. "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ".
pub fn generate_recovery_code() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 24];
    rng.fill_bytes(&mut bytes);
    let chars: String = bytes
        .iter()
        .map(|b| RECOVERY_CODE_ALPHABET[(b % RECOVERY_CODE_ALPHABET.len() as u8) as usize] as char)
        .collect();
    chars
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && i % 4 == 0 { Some('-') } else { None }
                .into_iter()
                .chain(std::iter::once(c))
        })
        .collect()
}

fn argon2id() -> Argon2<'static> {
    Argon2::default()
}

fn normalize_pepper(pepper: Option<&str>) -> Vec<u8> {
    pepper.map(|p| p.as_bytes().to_vec()).unwrap_or_default()
}

/// Hash a recovery code for server-side verification. Optional application
/// pepper can be prepended to mitigate rainbow-table attacks if the database
/// is compromised.
pub fn hash_recovery_code(code: &str, pepper: Option<&str>) -> Result<String> {
    let normalized = normalize_recovery_code(code);
    let with_pepper = [normalize_pepper(pepper).as_slice(), normalized.as_bytes()].concat();
    let salt = SaltString::generate(&mut OsRng);
    argon2id()
        .hash_password(&with_pepper, &salt)
        .map(|h| h.to_string())
        .map_err(|e| NivritError::Internal(e.to_string()))
}

/// Verify a user-supplied recovery code against its stored hash.
pub fn verify_recovery_code(code: &str, hash: &str, pepper: Option<&str>) -> Result<bool> {
    let normalized = normalize_recovery_code(code);
    let with_pepper = [normalize_pepper(pepper).as_slice(), normalized.as_bytes()].concat();
    let parsed = PasswordHash::new(hash).map_err(|e| NivritError::Internal(e.to_string()))?;
    Ok(argon2id().verify_password(&with_pepper, &parsed).is_ok())
}

/// Derive a 32-byte recovery encryption key from the recovery code. The same
/// code always produces the same key (deterministic), which is required to
/// decrypt the recovery-encrypted private key at reset time. Security rests on
/// the entropy of the recovery code itself.
pub fn derive_recovery_key(code: &str, pepper: Option<&str>) -> Result<[u8; 32]> {
    let normalized = normalize_recovery_code(code);
    let with_pepper = [normalize_pepper(pepper).as_slice(), normalized.as_bytes()].concat();
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(&with_pepper, RECOVERY_SALT, &mut out)
        .map_err(|e| NivritError::Internal(e.to_string()))?;
    Ok(out)
}

fn normalize_recovery_code(code: &str) -> String {
    code.to_ascii_uppercase().replace('-', "")
}

pub fn encrypt_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    Ok((ciphertext, nonce.to_vec()))
}

pub fn decrypt_with_key(ciphertext: &[u8], nonce: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| NivritError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_roundtrip() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), 29); // 24 chars + 5 dashes
        let hash = hash_recovery_code(&code, None).unwrap();
        assert!(verify_recovery_code(&code, &hash, None).unwrap());
        assert!(!verify_recovery_code(&generate_recovery_code(), &hash, None).unwrap());
    }

    #[test]
    fn recovery_key_derivation_is_deterministic() {
        let code = generate_recovery_code();
        let k1 = derive_recovery_key(&code, Some("pepper")).unwrap();
        let k2 = derive_recovery_key(&code, Some("pepper")).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_with_key() {
        let key = [1u8; 32];
        let plain = b"private-key-material";
        let (ct, nonce) = encrypt_with_key(plain, &key).unwrap();
        let decrypted = decrypt_with_key(&ct, &nonce, &key).unwrap();
        assert_eq!(decrypted, plain);
    }
}
