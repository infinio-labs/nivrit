//! Short-lived, server-signed tokens that bind the two-step OAuth flow.
//!
//! Two distinct vulnerabilities are closed here:
//!
//! - **State CSRF:** `oauth_authorize` issues a signed `state` and
//!   `oauth_callback` rejects any `state` it did not sign, so an attacker can't
//!   feed an arbitrary `code`/`state` pair into the callback.
//!
//! - **Account pre-hijack:** the identity proven during `oauth_callback`
//!   (`provider` + `provider_user_id` + `email`) is sealed into a signed
//!   `setup_token`. `oauth_setup` trusts only the contents of that token, never
//!   raw client-supplied identity fields, so a caller cannot register an account
//!   bound to a victim's OAuth identity.
//!
//! Both tokens are HMAC-signed with the same `auth_secret` as session JWTs and
//! carry an `exp` claim that `jsonwebtoken` validates on decode.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use nivrit_core::{NivritError, Result};
use rand::TryRng;
use serde::{Deserialize, Serialize};

const STATE_TTL_SECS: i64 = 600; // 10 minutes
const SETUP_TTL_SECS: i64 = 600; // 10 minutes

#[derive(Serialize, Deserialize)]
struct StateClaims {
    purpose: String,
    provider: String,
    nonce: String,
    exp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct SetupClaims {
    purpose: String,
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    exp: i64,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("operating-system RNG failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn enc(secret: &str, claims: &impl Serialize) -> Result<String> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| NivritError::Internal(e.to_string()))
}

fn dec<T: for<'de> Deserialize<'de>>(secret: &str, token: &str) -> Result<T> {
    decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| NivritError::Unauthorized)
}

/// Issue a signed `state` value for the authorize step.
pub fn issue_state(secret: &str, provider: &str) -> Result<String> {
    enc(
        secret,
        &StateClaims {
            purpose: "oauth_state".into(),
            provider: provider.into(),
            nonce: random_nonce(),
            exp: now() + STATE_TTL_SECS,
        },
    )
}

/// Verify a `state` returned to the callback was issued by us for this provider.
pub fn verify_state(secret: &str, token: &str, provider: &str) -> Result<()> {
    let claims: StateClaims = dec(secret, token)?;
    if claims.purpose != "oauth_state" || claims.provider != provider {
        return Err(NivritError::Unauthorized);
    }
    Ok(())
}

/// Seal a proven OAuth identity into a token the setup step can trust.
pub fn issue_setup(
    secret: &str,
    provider: &str,
    provider_user_id: &str,
    email: &str,
    name: Option<&str>,
) -> Result<String> {
    enc(
        secret,
        &SetupClaims {
            purpose: "oauth_setup".into(),
            provider: provider.into(),
            provider_user_id: provider_user_id.into(),
            email: email.into(),
            name: name.map(|s| s.to_string()),
            exp: now() + SETUP_TTL_SECS,
        },
    )
}

/// Recover the proven identity from a setup token. Fails on tampering/expiry.
pub fn verify_setup(secret: &str, token: &str) -> Result<SetupClaims> {
    let claims: SetupClaims = dec(secret, token)?;
    if claims.purpose != "oauth_setup" {
        return Err(NivritError::Unauthorized);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-at-least-32-bytes-long!!";

    #[test]
    fn state_roundtrip() {
        let s = issue_state(SECRET, "github").unwrap();
        assert!(verify_state(SECRET, &s, "github").is_ok());
    }

    #[test]
    fn state_rejects_wrong_provider() {
        let s = issue_state(SECRET, "github").unwrap();
        assert!(verify_state(SECRET, &s, "google").is_err());
    }

    #[test]
    fn state_rejects_wrong_secret() {
        let s = issue_state(SECRET, "github").unwrap();
        assert!(verify_state("another-secret-at-least-32-bytes!!!!", &s, "github").is_err());
    }

    #[test]
    fn setup_roundtrip_binds_identity() {
        let t = issue_setup(SECRET, "google", "uid-123", "a@b.com", Some("A")).unwrap();
        let claims = verify_setup(SECRET, &t).unwrap();
        assert_eq!(claims.provider, "google");
        assert_eq!(claims.provider_user_id, "uid-123");
        assert_eq!(claims.email, "a@b.com");
    }

    #[test]
    fn setup_rejects_state_token_used_as_setup() {
        let s = issue_state(SECRET, "github").unwrap();
        assert!(verify_setup(SECRET, &s).is_err());
    }

    #[test]
    fn setup_rejects_tampered_token() {
        let mut t = issue_setup(SECRET, "google", "uid-123", "a@b.com", None).unwrap();
        t.push('x');
        assert!(verify_setup(SECRET, &t).is_err());
    }
}
