use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::{NivritError, Result};
use totp_rs::{Algorithm, Builder, Secret, Totp};

const ISSUER: &str = "Nivrit";

/// Build a TOTP verifier for a base32 secret with nivrit's fixed parameters
/// (SHA-1, 6 digits, ±1 step skew, 30 s steps). totp-rs 6 only constructs via
/// its Builder, so all four call sites share this helper.
fn totp_for(secret: &str, account_name: &str) -> Result<Totp> {
    let secret = Secret::try_from_base32(secret)
        .map_err(|e| NivritError::Validation(format!("invalid TOTP secret: {e}")))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(ISSUER.to_string()))
        .with_account_name(account_name.to_string())
        .build()
        .map_err(|e| NivritError::Internal(format!("failed to build TOTP: {e}")))
}

/// Generate a new base32-encoded TOTP secret.
pub fn generate_secret() -> String {
    Secret::generate().to_base32()
}

/// Build an `otpauth://` URI suitable for QR-code rendering.
pub fn provisioning_uri(secret: &str, email: &str) -> Result<String> {
    totp_for(secret, email)?
        .to_url()
        .map_err(|e| NivritError::Internal(format!("failed to build TOTP URI: {e}")))
}

/// Verify a 6-digit TOTP code and return the matched time step, if any.
///
/// The step lets the caller persist the last accepted value and reject replays
/// of the same (or an older) code within its validity window. The ±1 skew
/// window is baked into the verifier (`skew = 1`).
pub fn verify_code_step(secret: &str, code: &str) -> Option<u64> {
    totp_for(secret, "user").ok()?.check_current(code)
}

/// Verify a 6-digit TOTP code against the secret.
pub fn verify_code(secret: &str, code: &str) -> bool {
    totp_for(secret, "user")
        .map(|totp| totp.check_current(code).is_some())
        .unwrap_or(false)
}

/// At-rest encryption for the TOTP secret using a server-side AES key.
///
/// Unlike the rest of Nivrit's key material, the TOTP secret genuinely must be
/// server-readable — the server is the party that verifies the code — so this is
/// server-side encryption under `NIVRIT_TOTP_ENCRYPTION_KEY`, not E2EE.
///
/// Returns `(ciphertext, nonce)`.
pub fn encrypt_secret(secret: &str, server_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher =
        Aes256Gcm::new_from_slice(server_key).expect("AES-256 key length is fixed at 32 bytes");
    let nonce = Nonce::<Aes256Gcm>::from(nivrit_crypto::random_bytes::<12>());
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_bytes())
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    Ok((ciphertext, nonce.to_vec()))
}

pub fn decrypt_secret(ciphertext: &[u8], nonce: &[u8], server_key: &[u8; 32]) -> Result<String> {
    let cipher =
        Aes256Gcm::new_from_slice(server_key).expect("AES-256 key length is fixed at 32 bytes");
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce)
        .map_err(|_| NivritError::Crypto("invalid AES-GCM nonce length".into()))?;
    let plain = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| NivritError::Crypto(e.to_string()))?;
    String::from_utf8(plain).map_err(|e| NivritError::Internal(e.to_string()))
}

pub fn decode_server_key(b64: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| NivritError::Validation(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(NivritError::Validation(
            "TOTP encryption key must be 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_code(secret: &str) -> String {
        let totp = totp_for(secret, "user").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        totp.generate(now).to_string()
    }

    #[test]
    fn verify_code_step_accepts_current_and_returns_step() {
        let secret = generate_secret();
        let code = current_code(&secret);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = verify_code_step(&secret, &code).expect("current code must verify");
        assert_eq!(step, now / 30);
    }

    #[test]
    fn verify_code_step_rejects_garbage() {
        let secret = generate_secret();
        assert!(
            verify_code_step(&secret, "000000").is_none()
                || verify_code_step(&secret, "999999").is_none()
        );
    }
}
