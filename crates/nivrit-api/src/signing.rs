//! Post-quantum signing of audit-log entries.
//!
//! Each audit-log row carries a detached ML-DSA-65 signature over a canonical
//! JSON representation of the event. This provides non-repudiation for the
//! audit trail independent of the transport-layer TLS or JWT mechanisms.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SubsecRound, Utc};
use nivrit_core::{NivritError, Result};
use nivrit_crypto::signatures::{
    MlDsa65Signer, MlDsa65Verifier, SignatureAlgorithm, Signer as _, Verifier as _,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Canonical message signed for each audit-log entry.
///
/// Field order is fixed so that serialization is deterministic. All UUIDs are
/// serialized as hyphenated strings and `created_at` as an RFC 3339 timestamp.
///
/// Note: `secret_id` is intentionally excluded from the signed payload. Audit
/// logs keep a `secret_id` column for convenience, but PostgreSQL sets it to
/// `NULL` when a secret is deleted (`ON DELETE SET NULL`). If the signature
/// depended on `secret_id`, deleting a secret would invalidate the signatures
/// of all prior audit entries for that key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogMessage {
    pub project_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub user_id: Uuid,
    pub action: String,
    pub key: String,
    pub created_at: String,
}

impl AuditLogMessage {
    pub fn new(
        project_id: Uuid,
        environment_id: Option<Uuid>,
        user_id: Uuid,
        action: &str,
        key: &str,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            project_id,
            environment_id,
            user_id,
            action: action.to_string(),
            key: key.to_string(),
            // Truncate to microseconds before signing so the canonical payload
            // matches the value that PostgreSQL timestamptz will store.
            created_at: created_at.trunc_subsecs(6).to_rfc3339(),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| NivritError::Crypto(e.to_string()))
    }
}

/// The signature material stored alongside an audit-log row.
#[derive(Debug, Clone)]
pub struct SignedAuditLog {
    pub algorithm: String,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Service that signs audit-log messages with an ML-DSA-65 key.
#[derive(Clone)]
pub struct SignatureService {
    signer: std::sync::Arc<MlDsa65Signer>,
}

impl SignatureService {
    /// Build a service from a 32-byte seed. The same seed always produces the
    /// same key pair, so signatures remain verifiable across restarts.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signer: std::sync::Arc::new(MlDsa65Signer::from_seed(seed)),
        }
    }

    /// Build a service from a base64-encoded 32-byte seed.
    pub fn from_seed_b64(seed_b64: &str) -> Result<Self> {
        let bytes = STANDARD
            .decode(seed_b64)
            .map_err(|e| NivritError::Crypto(format!("invalid signing key seed: {e}")))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            NivritError::Crypto("signing key seed must be 32 bytes (base64 encoded)".into())
        })?;
        Ok(Self::from_seed(&seed))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.signer
            .public_key()
            .expect("ML-DSA public key export must succeed")
    }

    pub fn algorithm(&self) -> String {
        self.signer.algorithm().as_str().to_string()
    }

    /// Sign an audit-log message.
    pub fn sign_audit_log(&self, msg: &AuditLogMessage) -> Result<SignedAuditLog> {
        let bytes = msg.canonical_bytes()?;
        let signature = self.signer.sign(&bytes)?;
        Ok(SignedAuditLog {
            algorithm: self.algorithm(),
            signature,
            public_key: self.public_key(),
        })
    }

    /// Verify an audit-log signature.
    pub fn verify_audit_log(msg: &AuditLogMessage, signed: &SignedAuditLog) -> Result<()> {
        let bytes = msg.canonical_bytes()?;
        let algorithm = signed
            .algorithm
            .parse::<SignatureAlgorithm>()
            .map_err(|_| {
                NivritError::Crypto(format!("unknown signature algorithm: {}", signed.algorithm))
            })?;
        match algorithm {
            SignatureAlgorithm::MlDsa65 => {
                let verifier = MlDsa65Verifier::from_public_key(&signed.public_key)?;
                verifier.verify(&bytes, &signed.signature)
            }
            other => Err(NivritError::Crypto(format!(
                "audit signature algorithm not supported: {}",
                other.as_str()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> SignatureService {
        SignatureService::from_seed(&[7u8; 32])
    }

    fn message() -> AuditLogMessage {
        AuditLogMessage::new(
            Uuid::nil(),
            Some(Uuid::nil()),
            Uuid::nil(),
            "read",
            "API_KEY",
            Utc::now(),
        )
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let svc = service();
        let msg = message();
        let signed = svc.sign_audit_log(&msg).unwrap();
        SignatureService::verify_audit_log(&msg, &signed).unwrap();
    }

    #[test]
    fn tampered_message_fails_verification() {
        let svc = service();
        let mut msg = message();
        let signed = svc.sign_audit_log(&msg).unwrap();
        msg.key = "OTHER_KEY".into();
        assert!(SignatureService::verify_audit_log(&msg, &signed).is_err());
    }

    #[test]
    fn wrong_seed_fails_verification() {
        let svc = service();
        let msg = message();
        let signed = svc.sign_audit_log(&msg).unwrap();

        let other = SignatureService::from_seed(&[9u8; 32]);
        let other_signed = SignedAuditLog {
            algorithm: signed.algorithm,
            signature: signed.signature,
            public_key: other.public_key(),
        };
        assert!(SignatureService::verify_audit_log(&msg, &other_signed).is_err());
    }
}
