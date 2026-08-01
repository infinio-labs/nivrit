//! Post-quantum signature support.
//!
//! Nivrit signs audit-log entries with pure ML-DSA-65 (see
//! `nivrit-api/src/signing.rs`) rather than a hybrid classical+ML-DSA scheme.
//! An earlier draft of this comment called hybrid signing "the recommended
//! deployment pattern" without the codebase ever implementing it -- that was
//! aspirational, not descriptive, and has been corrected (see `RESEARCH.md`
//! §4 and §9.1). Pure ML-DSA-65 was kept deliberately: audit-log signatures
//! are already re-verified against a hash chain (`entry_hash`/`prev_hash` in
//! `nivrit-api/src/signing.rs`), so the marginal benefit of a second classical
//! signature is smaller here than in a context with no such chain, and adding
//! one now would mean re-signing or dual-signing every future entry against a
//! second key this crate does not otherwise need. If ML-DSA is ever broken and
//! a hybrid becomes necessary, add it as a second `Signer` behind the same
//! trait boundary below rather than replacing this one, so historical
//! signatures remain verifiable.
//!
//! This module provides concrete ML-DSA-65/87 implementations behind the
//! `pq-signatures` feature. Ed25519/ECDSA and other parameter sets can be added
//! behind the same trait boundary.

use nivrit_core::{NivritError, Result};

#[cfg(feature = "pq-signatures")]
use ml_dsa::{
    Generate as _, KeyExport as _, Keypair as _, SignatureEncoding as _,
    Signer as MlDsaSignerTrait, Verifier as MlDsaVerifierTrait,
};
/// Supported signature schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Ed25519 (classical, fast, compact).
    Ed25519,
    /// ECDSA on P-256 (classical, widely supported).
    EcdsaP256,
    /// ML-DSA-65 (NIST PQC, lattice-based).
    MlDsa65,
    /// ML-DSA-87 (higher security level).
    MlDsa87,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256 => "ecdsa-p256",
            SignatureAlgorithm::MlDsa65 => "ml-dsa-65",
            SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
        }
    }
}

impl std::str::FromStr for SignatureAlgorithm {
    type Err = NivritError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ed25519" => Ok(SignatureAlgorithm::Ed25519),
            "ecdsa-p256" => Ok(SignatureAlgorithm::EcdsaP256),
            "ml-dsa-65" => Ok(SignatureAlgorithm::MlDsa65),
            "ml-dsa-87" => Ok(SignatureAlgorithm::MlDsa87),
            _ => Err(NivritError::Crypto(format!(
                "unknown signature algorithm: {s}"
            ))),
        }
    }
}

/// Abstraction over a signing key.
pub trait Signer: Send + Sync {
    /// Return the algorithm used by this signer.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Sign a message and return the signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Return the public key bytes used to verify signatures from this signer.
    fn public_key(&self) -> Result<Vec<u8>>;
}

/// Abstraction over a signature verifier.
pub trait Verifier: Send + Sync {
    /// Verify a signature for a message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}

// ============================================================================
// ML-DSA
// ============================================================================

#[cfg(feature = "pq-signatures")]
mod ml_dsa_impl {
    use super::*;

    macro_rules! impl_ml_dsa {
        ($name:ident, $verifier:ident, $params:ty, $variant:expr, $pretty:literal) => {
            pub struct $name {
                signing_key: ml_dsa::SigningKey<$params>,
            }

            impl $name {
                /// Generate a new key pair.
                pub fn generate() -> Self {
                    Self {
                        signing_key: ml_dsa::SigningKey::generate(),
                    }
                }

                /// Construct from a 32-byte seed.
                pub fn from_seed(seed: &[u8; 32]) -> Self {
                    Self {
                        signing_key: ml_dsa::SigningKey::from_seed(&ml_dsa::Seed::from(*seed)),
                    }
                }

                /// Create a verifier for this signer's public key.
                pub fn verifier(&self) -> $verifier {
                    $verifier {
                        verifying_key: self.signing_key.verifying_key(),
                    }
                }
            }

            impl Signer for $name {
                fn algorithm(&self) -> SignatureAlgorithm {
                    $variant
                }

                fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                    let sig = MlDsaSignerTrait::sign(&self.signing_key, message);
                    Ok(sig.to_bytes().to_vec())
                }

                fn public_key(&self) -> Result<Vec<u8>> {
                    Ok(self.signing_key.verifying_key().to_bytes().to_vec())
                }
            }

            pub struct $verifier {
                verifying_key: ml_dsa::VerifyingKey<$params>,
            }

            impl $verifier {
                /// Construct from raw public key bytes.
                pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
                    let enc: ml_dsa::EncodedVerifyingKey<$params> =
                        bytes.try_into().map_err(|_| {
                            NivritError::Crypto(format!("invalid {} public key length", $pretty))
                        })?;
                    Ok(Self {
                        verifying_key: ml_dsa::VerifyingKey::decode(&enc),
                    })
                }
            }

            impl Verifier for $verifier {
                fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
                    let sig: ml_dsa::Signature<$params> = signature.try_into().map_err(|_| {
                        NivritError::Crypto(format!("invalid {} signature length", $pretty))
                    })?;
                    MlDsaVerifierTrait::verify(&self.verifying_key, message, &sig).map_err(|e| {
                        NivritError::Crypto(format!("{} verify failed: {e:?}", $pretty))
                    })
                }
            }
        };
    }

    impl_ml_dsa!(
        MlDsa65Signer,
        MlDsa65Verifier,
        ml_dsa::MlDsa65,
        SignatureAlgorithm::MlDsa65,
        "ml-dsa-65"
    );
    impl_ml_dsa!(
        MlDsa87Signer,
        MlDsa87Verifier,
        ml_dsa::MlDsa87,
        SignatureAlgorithm::MlDsa87,
        "ml-dsa-87"
    );
}

#[cfg(feature = "pq-signatures")]
pub use ml_dsa_impl::{MlDsa65Signer, MlDsa65Verifier, MlDsa87Signer, MlDsa87Verifier};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_roundtrip() {
        for alg in [
            SignatureAlgorithm::Ed25519,
            SignatureAlgorithm::EcdsaP256,
            SignatureAlgorithm::MlDsa65,
            SignatureAlgorithm::MlDsa87,
        ] {
            assert_eq!(alg.as_str().parse::<SignatureAlgorithm>().unwrap(), alg);
        }
    }

    #[test]
    fn unknown_algorithm_errors() {
        assert!("rsa-pss".parse::<SignatureAlgorithm>().is_err());
        assert!("slh-dsa-sha2-128s".parse::<SignatureAlgorithm>().is_err());
        assert!("slh-dsa-sha2-256s".parse::<SignatureAlgorithm>().is_err());
    }

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn ml_dsa_65_sign_verify_roundtrip() {
        let signer = MlDsa65Signer::generate();
        let verifier = signer.verifier();
        let msg = b"hello ml-dsa";
        let sig = signer.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn ml_dsa_65_wrong_message_fails() {
        let signer = MlDsa65Signer::generate();
        let verifier = signer.verifier();
        let sig = signer.sign(b"hello").unwrap();
        assert!(verifier.verify(b"world", &sig).is_err());
    }

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn ml_dsa_87_sign_verify_roundtrip() {
        let signer = MlDsa87Signer::generate();
        let verifier = signer.verifier();
        let msg = b"hello ml-dsa-87";
        let sig = signer.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }
}
