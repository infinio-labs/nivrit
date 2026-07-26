use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};

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

/// Domain separator for the deterministic salt used by [`derive_auth_hash`].
const AUTH_SALT_DOMAIN: &[u8] = b"nivrit-auth-v1";
/// Domain separator for the deterministic salt used by [`derive_recovery_auth_hash`].
const RECOVERY_AUTH_SALT_DOMAIN: &[u8] = b"nivrit-recovery-auth-v1";
/// Domain separator for the salt used by `recovery::derive_recovery_key`.
const RECOVERY_KEY_SALT_DOMAIN: &[u8] = b"nivrit-recovery-key-v1";

/// Per-user salt for the recovery *key* derivation.
///
/// Kept here next to the other domain separators so every derivation Nivrit
/// performs is visible in one place and no two can accidentally collide.
pub(crate) fn recovery_key_salt(email: &str) -> [u8; 16] {
    deterministic_salt(RECOVERY_KEY_SALT_DOMAIN, email)
}

/// Build a deterministic 16-byte Argon2 salt from a domain tag and an identity.
///
/// The identity is lowercased so that a user typing `User@Example.com` derives
/// the same value as `user@example.com`.
fn deterministic_salt(domain: &[u8], identity: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b"\x00");
    hasher.update(identity.trim().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}

/// Derive the *authentication* hash that a client sends to the server in place
/// of the master password.
///
/// This is the client half of Nivrit's split-derivation scheme. The master
/// password never leaves the client; two independent values are derived from it:
///
/// - this authentication hash, salted deterministically with the user's email so
///   that any client (browser, CLI, helper) can recompute it, and
/// - the encryption key from [`derive_key`], salted with a random per-user value
///   stored alongside the encrypted private key.
///
/// Because the two use different salts, knowing one reveals nothing about the
/// other: a server that stores (and even a server that logs) the authentication
/// hash still cannot derive the key that unwraps the user's private key.
///
/// The server treats the returned value as an opaque credential and stores only
/// `hash_password(auth_hash)`, so a database leak does not yield a replayable
/// credential either.
pub fn derive_auth_hash(password: &[u8], email: &str) -> [u8; 32] {
    let salt = deterministic_salt(AUTH_SALT_DOMAIN, email);
    derive_key(password, &salt)
}

/// Derive the authentication hash for a recovery code.
///
/// Same split as [`derive_auth_hash`]: the server verifies this value to release
/// the recovery blob, while the recovery *key* that actually decrypts the blob is
/// derived separately on the client and never transmitted.
pub fn derive_recovery_auth_hash(recovery_code: &str, email: &str) -> [u8; 32] {
    let normalized = recovery_code.to_ascii_uppercase().replace('-', "");
    let salt = deterministic_salt(RECOVERY_AUTH_SALT_DOMAIN, email);
    derive_key(normalized.as_bytes(), &salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::random_bytes;

    #[test]
    fn auth_hash_is_deterministic_and_email_normalized() {
        let a = derive_auth_hash(b"hunter2", "User@Example.com");
        let b = derive_auth_hash(b"hunter2", "  user@example.com  ");
        assert_eq!(a, b, "email must be normalized before salting");
    }

    #[test]
    fn auth_hash_differs_per_email_and_password() {
        let base = derive_auth_hash(b"hunter2", "a@example.com");
        assert_ne!(base, derive_auth_hash(b"hunter2", "b@example.com"));
        assert_ne!(base, derive_auth_hash(b"hunter3", "a@example.com"));
    }

    /// The whole point of the split: the value sent to the server must not equal
    /// (or reveal) the key that unwraps the private key.
    #[test]
    fn auth_hash_is_independent_of_encryption_key() {
        let password = b"correct-horse-battery-staple";
        let email = "user@example.com";
        let auth = derive_auth_hash(password, email);

        // The encryption key uses a random per-user salt.
        let enc_salt = random_bytes::<16>();
        let enc = derive_key(password, &enc_salt);
        assert_ne!(auth, enc);

        // Even if an attacker guesses that the salt was derived from the email,
        // the domain separator keeps the two derivations apart.
        let same_salt_as_auth = deterministic_salt(AUTH_SALT_DOMAIN, email);
        let recovery_salt = deterministic_salt(RECOVERY_AUTH_SALT_DOMAIN, email);
        assert_ne!(same_salt_as_auth, recovery_salt);
    }

    #[test]
    fn recovery_auth_hash_normalizes_formatting() {
        let email = "user@example.com";
        let dashed = derive_recovery_auth_hash("ABCD-EFGH-JKLM", email);
        let bare = derive_recovery_auth_hash("abcdefghjklm", email);
        assert_eq!(dashed, bare, "dashes and case must not affect the hash");
    }

    #[test]
    fn recovery_auth_hash_differs_from_password_auth_hash() {
        // A recovery code must never be usable as a password credential.
        let shared = "shared-secret-value";
        let email = "user@example.com";
        assert_ne!(
            derive_auth_hash(shared.as_bytes(), email),
            derive_recovery_auth_hash(shared, email)
        );
    }

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
