use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use nivrit_core::{NivritError, Result};

// OWASP-aligned Argon2id parameters for credential storage.
// m = 64 MiB, t = 3 passes, p = 1 lane, 32-byte output.
// Adjust via environment-specific benchmarks; aim for ~100-500 ms per hash.
//
// The inputs here are client-derived authentication hashes, not raw passwords
// (see the crate docs). They already carry a full Argon2id pass, so this second
// hash exists to make a database leak non-replayable rather than to add
// brute-force cost. The parameters stay high anyway: it is one hash per login,
// and it keeps a single code path for every credential the server stores.
fn argon2id_params() -> Params {
    Params::new(64 * 1024, 3, 1, Some(32))
        .expect("configured Argon2id parameters are within valid bounds")
}

fn argon2id_hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params())
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::encode_b64(&nivrit_crypto::random_bytes::<16>())
        .map_err(|e| NivritError::Internal(e.to_string()))?;
    let argon2 = argon2id_hasher();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| NivritError::Internal(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| NivritError::Internal(e.to_string()))?;
    let argon2 = argon2id_hasher();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hashing_roundtrip() {
        let password = "a-sufficiently-long-test-password";
        let hash = hash_password(password).expect("hash should succeed");
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password(password, &hash).expect("verify should succeed"));
        assert!(!verify_password("wrong-password", &hash).expect("verify should return false"));
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let password = "another-test-password";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        assert_ne!(hash1, hash2, "salts must be unique per hash");
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn verify_invalid_hash_returns_error() {
        let result = verify_password("password", "definitely-not-argon2");
        assert!(result.is_err());
    }

    #[test]
    fn empty_password_can_be_hashed_and_verified() {
        let hash = hash_password("").unwrap();
        assert!(verify_password("", &hash).unwrap());
        assert!(!verify_password("x", &hash).unwrap());
    }
}
