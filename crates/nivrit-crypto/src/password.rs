use argon2::{Algorithm, Argon2, Params, Version};

// Argon2id parameters for deriving encryption keys from a user password.
// These are intentionally memory-hard to resist GPU/ASIC brute force.
// m = 64 MiB, t = 3 passes, p = 1 lane, 32-byte output.
fn argon2id_params() -> Params {
    Params::new(64 * 1024, 3, 1, Some(32))
        .expect("configured Argon2id parameters are within valid bounds")
}

fn argon2id_hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2id_params())
}

/// Derive a 32-byte symmetric key from `password` and `salt` using Argon2id.
///
/// The salt must be at least 8 bytes (16 bytes is recommended) and must be
/// unique per password/secret. This function is deterministic: the same
/// password and salt always produce the same key.
pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2id_hasher()
        .hash_password_into(password, salt, &mut key)
        .expect("argon2id output length is valid");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    #[test]
    fn derive_key_is_deterministic() {
        let password = b"correct-horse-battery-staple";
        let salt = random_bytes::<16>();
        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let password = b"correct-horse-battery-staple";
        let salt1 = random_bytes::<16>();
        let salt2 = random_bytes::<16>();
        let key1 = derive_key(password, &salt1);
        let key2 = derive_key(password, &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derived_key_is_32_bytes() {
        let key = derive_key(b"password", &random_bytes::<16>());
        assert_eq!(key.len(), 32);
    }
}
