//! Recovery-code generation and key derivation.
//!
//! These primitives live in `nivrit-crypto` rather than `nivrit-auth` because
//! they run entirely on the **client**: the browser (via WASM), the CLI, and the
//! SDK crypto-helper all need them, and the server must never see a recovery
//! code. The server only ever stores `hash_password(recovery_auth_hash)`.
//!
//! Two independent values are derived from one recovery code, mirroring the
//! password split in [`crate::password`]:
//!
//! - the *recovery key*, which decrypts the user's private key, and
//! - the *recovery authentication hash*, which the server verifies to release
//!   the recovery blob.
//!
//! Different salts keep them independent, so a server holding the authentication
//! hash cannot derive the key.

use nivrit_core::Result;

use crate::keys::random_bytes;
use crate::password::derive_key;
use crate::suite::CryptoSuite;

/// Alphabet for human-transcribed recovery codes. Omits `0`/`O` and `I`/`L`,
/// which are the pairs people most often confuse when reading a code aloud.
const RECOVERY_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Number of characters in a generated recovery code, before dashes.
const RECOVERY_CODE_LEN: usize = 24;

/// Generate a human-friendly recovery code, e.g. `ABCD-EFGH-JKLM-NPQR-STUV-WXYZ`.
///
/// 24 characters from a 32-symbol alphabet is 120 bits of entropy. The alphabet
/// length divides 256 exactly, so reducing a random byte modulo its length is
/// uniform — there is no modulo bias to correct for.
pub fn generate_recovery_code() -> String {
    let bytes = random_bytes::<RECOVERY_CODE_LEN>();
    let chars: String = bytes
        .iter()
        .map(|b| RECOVERY_CODE_ALPHABET[(b % RECOVERY_CODE_ALPHABET.len() as u8) as usize] as char)
        .collect();
    chars
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && i.is_multiple_of(4) {
                Some('-')
            } else {
                None
            }
            .into_iter()
            .chain(std::iter::once(c))
        })
        .collect()
}

/// Normalize a user-typed recovery code: uppercase, dashes stripped.
pub fn normalize_recovery_code(code: &str) -> String {
    code.to_ascii_uppercase().replace(['-', ' '], "")
}

/// Derive the 32-byte key that encrypts the user's private key for recovery.
///
/// Deterministic in (code, email) so the client can rebuild it at reset time.
/// Salted per user via the email, so two users who somehow received the same
/// code still derive different keys, and uses the same 64 MiB / t=3 Argon2id
/// parameters as every other key derivation in Nivrit.
///
/// This value must never be sent to the server. Send
/// [`crate::password::derive_recovery_auth_hash`] instead.
pub fn derive_recovery_key(code: &str, email: &str) -> [u8; 32] {
    let normalized = normalize_recovery_code(code);
    let salt = crate::password::recovery_key_salt(email);
    derive_key(normalized.as_bytes(), &salt)
}

/// Encrypt the plaintext private key under a recovery key.
///
/// Returns `(ciphertext, nonce)`.
pub fn encrypt_private_key_for_recovery(
    private_key: &[u8],
    recovery_key: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let encrypted = CryptoSuite::Aes256GcmV1.encrypt(private_key, recovery_key)?;
    Ok((encrypted.ciphertext, encrypted.nonce))
}

/// Decrypt a recovery blob produced by [`encrypt_private_key_for_recovery`].
pub fn decrypt_private_key_from_recovery(
    ciphertext: &[u8],
    nonce: &[u8],
    recovery_key: &[u8; 32],
) -> Result<Vec<u8>> {
    CryptoSuite::Aes256GcmV1.decrypt(ciphertext, nonce, recovery_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_code_has_expected_shape() {
        let code = generate_recovery_code();
        assert_eq!(code.len(), RECOVERY_CODE_LEN + 5, "24 chars plus 5 dashes");
        assert!(code
            .chars()
            .all(|c| c == '-' || RECOVERY_CODE_ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn generated_codes_are_distinct() {
        assert_ne!(generate_recovery_code(), generate_recovery_code());
    }

    #[test]
    fn normalization_is_format_insensitive() {
        assert_eq!(
            normalize_recovery_code("abcd-efgh jklm"),
            "ABCDEFGHJKLM".to_string()
        );
    }

    #[test]
    fn recovery_key_is_deterministic_and_per_user() {
        let code = generate_recovery_code();
        let k1 = derive_recovery_key(&code, "user@example.com");
        let k2 = derive_recovery_key(&code, "USER@example.com");
        assert_eq!(k1, k2, "email is normalized, so the key must match");
        assert_ne!(k1, derive_recovery_key(&code, "other@example.com"));
    }

    #[test]
    fn recovery_key_is_independent_of_the_auth_hash_sent_to_the_server() {
        let code = generate_recovery_code();
        let email = "user@example.com";
        let key = derive_recovery_key(&code, email);
        let auth_hash = crate::password::derive_recovery_auth_hash(&code, email);
        assert_ne!(
            key, auth_hash,
            "the server-visible hash must not equal the decryption key"
        );
    }

    #[test]
    fn recovery_blob_roundtrip() {
        let code = generate_recovery_code();
        let key = derive_recovery_key(&code, "user@example.com");
        let private_key = b"a-serialized-hybrid-private-key";

        let (ciphertext, nonce) = encrypt_private_key_for_recovery(private_key, &key).unwrap();
        let recovered = decrypt_private_key_from_recovery(&ciphertext, &nonce, &key).unwrap();
        assert_eq!(recovered, private_key);
    }

    #[test]
    fn recovery_blob_rejects_the_wrong_code() {
        let email = "user@example.com";
        let key = derive_recovery_key(&generate_recovery_code(), email);
        let wrong = derive_recovery_key(&generate_recovery_code(), email);

        let (ciphertext, nonce) = encrypt_private_key_for_recovery(b"private", &key).unwrap();
        assert!(decrypt_private_key_from_recovery(&ciphertext, &nonce, &wrong).is_err());
    }
}
