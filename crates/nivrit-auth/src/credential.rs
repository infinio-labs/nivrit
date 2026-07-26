//! Server-side storage of client-derived credentials.
//!
//! # Why this is a fast keyed hash and not Argon2id
//!
//! What the server receives is never a password. Under split derivation (ADR
//! 0002) it receives `auth_hash = Argon2id(password, salt = H(email))` — a
//! 32-byte value with the full entropy of the password behind it, but which can
//! only be produced by paying that Argon2id cost.
//!
//! That changes what the stored hash has to do. Consider an attacker holding a
//! database dump who wants to authenticate as a user:
//!
//! - Brute-forcing the stored value's 32-byte preimage directly is 2^256. No
//!   choice of hash function matters at that scale.
//! - The only feasible path is guessing passwords — and for every guess they
//!   must run the *client's* 64 MiB Argon2id to produce a candidate `auth_hash`
//!   before they can even test it.
//!
//! So the brute-force cost is already paid, on the client side, by a derivation
//! the attacker cannot skip. Making the server-side hash *also* memory-hard adds
//! a second 64 MiB per guess, but it charges that same cost to every legitimate
//! login, and it turns unauthenticated registration into a request that forces
//! 128 MiB of server memory. That is a poor allocation: memory-hardness should
//! be spent where the attacker cannot avoid it and the defender pays least,
//! which is once on the user's own device — not per request on a shared server
//! under adversarial load. Raising the *client* parameters buys strictly more.
//!
//! What the stored value must still do is stay useless after a database leak,
//! and a keyed hash does that more completely than an unkeyed slow hash: the MAC
//! key lives in the server's configuration, not the database, so a dump alone
//! yields nothing to attack.
//!
//! This is the same reasoning that already applies to personal access tokens,
//! which are stored as a plain SHA-256 digest because they too are high-entropy.
//! Bitwarden uses this shape; 1Password avoids the question entirely with SRP.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use nivrit_core::{NivritError, Result};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Prefix identifying the stored format, so a future scheme can be introduced
/// without guessing what an existing row contains.
const FORMAT_PREFIX: &str = "hmac-sha256-v1$";

/// Domain separator for deriving the MAC key from the application secret.
const KEY_INFO: &[u8] = b"nivrit-credential-hash-v1";

/// Hashes and verifies the opaque credentials clients send in place of
/// passwords.
///
/// The MAC key is derived from the application secret rather than configured
/// separately, so deployments gain the pepper without another value to manage.
/// A distinct HKDF `info` keeps it independent of the JWT signing use of that
/// same secret.
#[derive(Clone)]
pub struct CredentialHasher {
    key: [u8; 32],
}

impl std::fmt::Debug for CredentialHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key, even accidentally via a derived Debug on AppState.
        f.debug_struct("CredentialHasher").finish_non_exhaustive()
    }
}

impl CredentialHasher {
    pub fn new(app_secret: &str) -> Self {
        let hkdf = Hkdf::<Sha256>::new(None, app_secret.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(KEY_INFO, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self { key }
    }

    fn mac(&self, credential: &str) -> Vec<u8> {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(credential.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Hash a credential for storage.
    pub fn hash(&self, credential: &str) -> String {
        format!("{FORMAT_PREFIX}{}", STANDARD.encode(self.mac(credential)))
    }

    /// Verify a credential against a stored hash.
    ///
    /// Compares in constant time: a byte-by-byte early exit would leak how much
    /// of a candidate MAC was correct, which is enough to forge one.
    pub fn verify(&self, credential: &str, stored: &str) -> Result<bool> {
        let encoded = stored.strip_prefix(FORMAT_PREFIX).ok_or_else(|| {
            NivritError::Internal("stored credential is in an unrecognised format".into())
        })?;
        let expected = STANDARD
            .decode(encoded)
            .map_err(|_| NivritError::Internal("stored credential is not valid base64".into()))?;

        let actual = self.mac(credential);
        Ok(actual.ct_eq(&expected).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "an-application-secret-of-sufficient-length";

    fn hasher() -> CredentialHasher {
        CredentialHasher::new(SECRET)
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hasher();
        let stored = h.hash("an-opaque-client-derived-credential");
        assert!(h
            .verify("an-opaque-client-derived-credential", &stored)
            .unwrap());
    }

    #[test]
    fn rejects_a_different_credential() {
        let h = hasher();
        let stored = h.hash("credential-one");
        assert!(!h.verify("credential-two", &stored).unwrap());
    }

    /// The point of the pepper: a database dump is useless without the
    /// application secret, because the MAC cannot be recomputed.
    #[test]
    fn a_different_application_secret_cannot_verify() {
        let stored = hasher().hash("credential");
        let other = CredentialHasher::new("a-completely-different-application-secret");
        assert!(!other.verify("credential", &stored).unwrap());
    }

    #[test]
    fn hashing_is_deterministic_for_the_same_key() {
        let h = hasher();
        assert_eq!(h.hash("credential"), h.hash("credential"));
    }

    #[test]
    fn stored_value_carries_its_format() {
        assert!(hasher().hash("credential").starts_with(FORMAT_PREFIX));
    }

    #[test]
    fn rejects_an_unrecognised_stored_format() {
        // An Argon2 PHC string from a previous scheme must error rather than
        // silently comparing false and looking like a wrong password.
        let err = hasher()
            .verify("credential", "$argon2id$v=19$m=65536,t=3,p=1$abc$def")
            .unwrap_err();
        assert!(matches!(err, NivritError::Internal(_)));
    }

    #[test]
    fn rejects_a_corrupt_stored_value() {
        let err = hasher()
            .verify("credential", &format!("{FORMAT_PREFIX}not-base64!!!"))
            .unwrap_err();
        assert!(matches!(err, NivritError::Internal(_)));
    }

    #[test]
    fn debug_does_not_leak_the_key() {
        assert!(!format!("{:?}", hasher()).contains("key"));
    }
}
