use chrono::{Duration, Utc};
use nivrit_core::{NivritError, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiry_seconds: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub mfa_pending: bool,
}

impl JwtConfig {
    pub fn sign(&self, user_id: Uuid, email: String) -> Result<String> {
        self.sign_with_mfa(user_id, email, false)
    }

    pub fn sign_with_mfa(&self, user_id: Uuid, email: String, mfa_pending: bool) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.expiry_seconds);
        let claims = Claims {
            sub: user_id,
            email,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            mfa_pending,
        };

        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| NivritError::Internal(e.to_string()))
    }

    pub fn verify(&self, token: &str) -> Result<Claims> {
        jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(self.secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|_| NivritError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(expiry_seconds: i64) -> JwtConfig {
        JwtConfig {
            secret: "test-secret-that-is-long-enough".into(),
            expiry_seconds,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let config = test_config(3600);
        let user_id = Uuid::new_v4();
        let token = config.sign(user_id, "test@example.com".into()).unwrap();
        let claims = config.verify(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, "test@example.com");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let config = test_config(3600);
        let token = config
            .sign(Uuid::new_v4(), "test@example.com".into())
            .unwrap();
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(config.verify(&tampered).is_err());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let config = test_config(3600);
        let token = config
            .sign(Uuid::new_v4(), "test@example.com".into())
            .unwrap();
        let other = JwtConfig {
            secret: "a-different-secret-of-sufficient-length".into(),
            expiry_seconds: 3600,
        };
        assert!(other.verify(&token).is_err());
    }

    #[test]
    fn verify_rejects_expired_token() {
        // Default jwt validation allows 60 seconds of leeway, so go well past it.
        let config = test_config(-3600);
        let token = config
            .sign(Uuid::new_v4(), "test@example.com".into())
            .unwrap();
        assert!(config.verify(&token).is_err());
    }

    #[test]
    fn verify_rejects_malformed_token() {
        let config = test_config(3600);
        assert!(config.verify("not-a-jwt").is_err());
    }
}
