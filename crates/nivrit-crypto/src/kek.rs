//! Key-encryption-key (KEK) backend abstraction.
//!
//! Nivrit stores user private keys encrypted under password-derived keys. In
//! enterprise deployments the password-derived key can itself be wrapped by a
//! KEK held in an HSM or cloud KMS, allowing centralized key escrow / recovery
//! without exposing the KEK to the application host.
//!
//! Backends are selected by enabling the corresponding feature:
//! - `kek-aws`    — AWS KMS wrapping using a symmetric customer master key.
//! - `kek-azure`  — Azure Key Vault key wrapping using an RSA key (`RSA-OAEP-256`).
//!
//! The trait is async because cloud KMS SDKs are asynchronous. Callers should
//! `.await` `wrap`/`unwrap` from within an async context.

use nivrit_core::{NivritError, Result};

/// A handle to a key-encryption-key backend.
pub trait KekBackend: Send + Sync {
    /// Wrap a plaintext data-encryption-key (DEK) with the KEK.
    fn wrap(&self, dek: &[u8]) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;

    /// Unwrap a DEK previously returned by `wrap`.
    fn unwrap(
        &self,
        ciphertext: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

/// Local KEK that performs wrapping in process memory using AES-256-GCM.
///
/// This is the default for self-hosted deployments. It provides the same
/// interface as HSM/KMS backends but offers no hardware protection.
pub struct LocalKek {
    key: Vec<u8>,
}

impl LocalKek {
    pub fn new(key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            return Err(NivritError::Crypto("local KEK key must be 32 bytes".into()));
        }
        Ok(Self { key })
    }
}

impl KekBackend for LocalKek {
    async fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
        };

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| NivritError::Crypto(format!("local KEK init failed: {e}")))?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, dek)
            .map_err(|e| NivritError::Crypto(format!("local KEK wrap failed: {e}")))?;

        let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    async fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

        if ciphertext.len() < 12 + 16 {
            return Err(NivritError::Crypto(
                "local KEK unwrap: ciphertext too short".into(),
            ));
        }
        let (nonce_bytes, sealed) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| NivritError::Crypto(format!("local KEK init failed: {e}")))?;
        cipher
            .decrypt(nonce, sealed)
            .map_err(|e| NivritError::Crypto(format!("local KEK unwrap failed: {e}")))
    }
}

// ============================================================================
// AWS KMS
// ============================================================================

#[cfg(feature = "kek-aws")]
pub struct AwsKmsKek {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[cfg(feature = "kek-aws")]
impl AwsKmsKek {
    /// Create a KEK backed by an AWS KMS symmetric key.
    ///
    /// Credentials and region are loaded from the environment using the
    /// standard AWS SDK credential chain.
    pub async fn new(key_id: String) -> Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self { client, key_id })
    }

    /// Create with an already-loaded SDK config (useful for tests or custom
    /// credential providers).
    pub fn from_config(config: &aws_config::SdkConfig, key_id: String) -> Self {
        let client = aws_sdk_kms::Client::new(config);
        Self { client, key_id }
    }
}

#[cfg(feature = "kek-aws")]
impl KekBackend for AwsKmsKek {
    async fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        let output = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(dek.to_vec()))
            .send()
            .await
            .map_err(|e| NivritError::Crypto(format!("AWS KMS encrypt failed: {e}")))?;

        output
            .ciphertext_blob
            .map(|b| b.into_inner())
            .ok_or_else(|| NivritError::Crypto("AWS KMS encrypt returned no ciphertext".into()))
    }

    async fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let output = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext.to_vec()))
            .send()
            .await
            .map_err(|e| NivritError::Crypto(format!("AWS KMS decrypt failed: {e}")))?;

        output
            .plaintext
            .map(|b| b.into_inner())
            .ok_or_else(|| NivritError::Crypto("AWS KMS decrypt returned no plaintext".into()))
    }
}

// ============================================================================
// Azure Key Vault
// ============================================================================

#[cfg(feature = "kek-azure")]
pub struct AzureKeyVaultKek {
    client: azure_security_keyvault_keys::KeyClient,
    key_name: String,
}

#[cfg(feature = "kek-azure")]
impl AzureKeyVaultKek {
    /// Create a KEK backed by an Azure Key Vault RSA key.
    ///
    /// Uses `DeveloperToolsCredential` (Azure CLI, etc.) for local development.
    /// For production, use [`Self::new_with_credential`].
    pub fn new(vault_url: &str, key_name: String) -> Result<Self> {
        let credential = azure_identity::DeveloperToolsCredential::new(None)
            .map_err(|e| NivritError::Crypto(format!("Azure credential failed: {e}")))?;
        Self::new_with_credential(vault_url, key_name, credential)
    }

    /// Create with an explicit token credential.
    pub fn new_with_credential(
        vault_url: &str,
        key_name: String,
        credential: std::sync::Arc<dyn azure_core::credentials::TokenCredential>,
    ) -> Result<Self> {
        let client = azure_security_keyvault_keys::KeyClient::new(vault_url, credential, None)
            .map_err(|e| NivritError::Crypto(format!("Azure Key Vault client failed: {e}")))?;
        Ok(Self { client, key_name })
    }
}

#[cfg(feature = "kek-azure")]
impl KekBackend for AzureKeyVaultKek {
    async fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        use azure_security_keyvault_keys::models::{EncryptionAlgorithm, KeyOperationParameters};

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(dek.to_vec()),
            ..Default::default()
        };

        let response = self
            .client
            .wrap_key(
                &self.key_name,
                parameters.try_into().map_err(|e| {
                    NivritError::Crypto(format!("Azure wrap parameters invalid: {e}"))
                })?,
                None,
            )
            .await
            .map_err(|e| NivritError::Crypto(format!("Azure Key Vault wrap failed: {e}")))?;

        response
            .into_model()
            .map_err(|e| NivritError::Crypto(format!("Azure wrap response invalid: {e}")))?
            .result
            .ok_or_else(|| NivritError::Crypto("Azure Key Vault wrap returned no result".into()))
    }

    async fn unwrap(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use azure_security_keyvault_keys::models::{EncryptionAlgorithm, KeyOperationParameters};

        let parameters = KeyOperationParameters {
            algorithm: Some(EncryptionAlgorithm::RsaOaep256),
            value: Some(ciphertext.to_vec()),
            ..Default::default()
        };

        let response = self
            .client
            .unwrap_key(
                &self.key_name,
                "",
                parameters.try_into().map_err(|e| {
                    NivritError::Crypto(format!("Azure unwrap parameters invalid: {e}"))
                })?,
                None,
            )
            .await
            .map_err(|e| NivritError::Crypto(format!("Azure Key Vault unwrap failed: {e}")))?;

        response
            .into_model()
            .map_err(|e| NivritError::Crypto(format!("Azure unwrap response invalid: {e}")))?
            .result
            .ok_or_else(|| NivritError::Crypto("Azure Key Vault unwrap returned no result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_kek_roundtrip() {
        let kek = LocalKek::new(vec![0u8; 32]).unwrap();
        let dek = b"super-secret-dek-thirty-two-bytes";
        let wrapped = kek.wrap(dek).await.unwrap();
        assert_ne!(wrapped, dek.as_slice());
        let unwrapped = kek.unwrap(&wrapped).await.unwrap();
        assert_eq!(unwrapped, dek.as_slice());
    }

    #[tokio::test]
    async fn local_kek_bad_key_length_fails() {
        assert!(LocalKek::new(vec![0u8; 16]).is_err());
    }

    #[tokio::test]
    async fn local_kek_tampered_ciphertext_fails() {
        let kek = LocalKek::new(vec![1u8; 32]).unwrap();
        let dek = b"another-secret-key-32-bytes-long";
        let mut wrapped = kek.wrap(dek).await.unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        assert!(kek.unwrap(&wrapped).await.is_err());
    }
}
