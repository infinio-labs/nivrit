use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::{NivritError, Result};
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "Nivrit";

/// Generate a new base32-encoded TOTP secret.
pub fn generate_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

/// Build an `otpauth://` URI suitable for QR-code rendering.
pub fn provisioning_uri(secret: &str, email: &str) -> Result<String> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| NivritError::Validation(format!("invalid TOTP secret: {}", e)))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER.to_string()),
        email.to_string(),
    )
    .map_err(|e| NivritError::Internal(format!("failed to build TOTP: {}", e)))?;
    Ok(totp.get_url())
}

/// Verify a 6-digit TOTP code and return the matched time step, if any.
///
/// The step lets the caller persist the last accepted value and reject replays
/// of the same (or an older) code within its validity window.
pub fn verify_code_step(secret: &str, code: &str) -> Option<u64> {
    let secret_bytes = Secret::Encoded(secret.to_string()).to_bytes().ok()?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER.to_string()),
        "user".to_string(),
    )
    .ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let step = now / 30;
    // Match the same ±1 skew window as `verify_code` (check(code, 1)).
    [step.saturating_sub(1), step, step + 1]
        .into_iter()
        .find(|&candidate| totp.generate(candidate * 30) == code)
}

/// Verify a 6-digit TOTP code against the secret.
pub fn verify_code(secret: &str, code: &str) -> bool {
    let Ok(secret_bytes) = Secret::Encoded(secret.to_string()).to_bytes() else {
        return false;
    };
    let Ok(totp) = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER.to_string()),
        "user".to_string(),
    ) else {
        return false;
    };
    totp.check(code, 1)
}

/// Simple at-rest encryption for the TOTP secret using a server-side AES key.
pub fn encrypt_secret(secret: &str, server_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    super::recovery::encrypt_with_key(secret.as_bytes(), server_key)
}

pub fn decrypt_secret(ciphertext: &[u8], nonce: &[u8], server_key: &[u8; 32]) -> Result<String> {
    let plain = super::recovery::decrypt_with_key(ciphertext, nonce, server_key)?;
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
        let bytes = Secret::Encoded(secret.to_string()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            bytes,
            Some(ISSUER.to_string()),
            "user".to_string(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        totp.generate(now)
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
