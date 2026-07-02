//! Post-quantum and hybrid signature support.
//!
//! Phase 4 of the Nivrit roadmap evaluates NIST-standardized post-quantum
//! signature schemes for long-lived audit signatures and non-repudiation:
//!
//! - **ML-DSA** (FIPS 204): lattice-based, fast signatures, moderate key sizes.
//! - **SLH-DSA** (FIPS 205): hash-based, small keys, large signatures, high
//!   confidence.
//!
//! For operational continuity a hybrid mode combining an ECDSA/P-256 or
//! Ed25519 classical signature with an ML-DSA/SLH-DSA PQ signature is the
//! recommended deployment pattern until PQ algorithms have broad ecosystem
//! support.
//!
//! This module provides concrete ML-DSA-65/87 and SLH-DSA-SHA2-128s/256s
//! implementations behind the `pq-signatures` feature. Ed25519/ECDSA and
//! other parameter sets can be added behind the same trait boundary.

use nivrit_core::{NivritError, Result};

#[cfg(feature = "pq-signatures")]
use ml_dsa::{
    Generate as _, KeyExport as _, Keypair as _, SignatureEncoding as _,
    Signer as MlDsaSignerTrait, Verifier as MlDsaVerifierTrait,
};
#[cfg(feature = "pq-signatures")]
use pqcrypto_sphincsplus::{sphincssha2128ssimple, sphincssha2256ssimple};
#[cfg(feature = "pq-signatures")]
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, VerificationError};

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
    /// SLH-DSA-SHA2-128s (hash-based, conservative).
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-256s (higher security level).
    SlhDsaSha2_256s,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256 => "ecdsa-p256",
            SignatureAlgorithm::MlDsa65 => "ml-dsa-65",
            SignatureAlgorithm::MlDsa87 => "ml-dsa-87",
            SignatureAlgorithm::SlhDsaSha2_128s => "slh-dsa-sha2-128s",
            SignatureAlgorithm::SlhDsaSha2_256s => "slh-dsa-sha2-256s",
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
            "slh-dsa-sha2-128s" => Ok(SignatureAlgorithm::SlhDsaSha2_128s),
            "slh-dsa-sha2-256s" => Ok(SignatureAlgorithm::SlhDsaSha2_256s),
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

// ============================================================================
// SLH-DSA
// ============================================================================

#[cfg(feature = "pq-signatures")]
mod slh_dsa_impl {
    use super::*;

    fn slh_verify_error(alg: &str, e: VerificationError) -> NivritError {
        let reason = match e {
            VerificationError::InvalidSignature => "invalid signature",
            VerificationError::UnknownVerificationError => "unknown verification error",
            _ => "verification error",
        };
        NivritError::Crypto(format!("{alg} verify failed: {reason}"))
    }

    // ------------------------------------------------------------------------
    // SLH-DSA-SHA2-128s
    // ------------------------------------------------------------------------

    pub struct SlhDsaSha2_128sSigner {
        secret_key: sphincssha2128ssimple::SecretKey,
        public_key: sphincssha2128ssimple::PublicKey,
    }

    impl SlhDsaSha2_128sSigner {
        pub fn generate() -> Self {
            let (pk, sk) = sphincssha2128ssimple::keypair();
            Self {
                secret_key: sk,
                public_key: pk,
            }
        }

        pub fn verifier(&self) -> SlhDsaSha2_128sVerifier {
            SlhDsaSha2_128sVerifier {
                public_key: self.public_key,
            }
        }
    }

    impl Signer for SlhDsaSha2_128sSigner {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::SlhDsaSha2_128s
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sig = sphincssha2128ssimple::detached_sign(message, &self.secret_key);
            Ok(sig.as_bytes().to_vec())
        }

        fn public_key(&self) -> Result<Vec<u8>> {
            Ok(self.public_key.as_bytes().to_vec())
        }
    }

    pub struct SlhDsaSha2_128sVerifier {
        public_key: sphincssha2128ssimple::PublicKey,
    }

    impl SlhDsaSha2_128sVerifier {
        pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
            let pk = sphincssha2128ssimple::PublicKey::from_bytes(bytes).map_err(|_| {
                NivritError::Crypto("invalid slh-dsa-sha2-128s public key length".into())
            })?;
            Ok(Self { public_key: pk })
        }
    }

    impl Verifier for SlhDsaSha2_128sVerifier {
        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
            let sig =
                sphincssha2128ssimple::DetachedSignature::from_bytes(signature).map_err(|_| {
                    NivritError::Crypto("invalid slh-dsa-sha2-128s signature length".into())
                })?;
            sphincssha2128ssimple::verify_detached_signature(&sig, message, &self.public_key)
                .map_err(|e| slh_verify_error("slh-dsa-sha2-128s", e))
        }
    }

    // ------------------------------------------------------------------------
    // SLH-DSA-SHA2-256s
    // ------------------------------------------------------------------------

    pub struct SlhDsaSha2_256sSigner {
        secret_key: sphincssha2256ssimple::SecretKey,
        public_key: sphincssha2256ssimple::PublicKey,
    }

    impl SlhDsaSha2_256sSigner {
        pub fn generate() -> Self {
            let (pk, sk) = sphincssha2256ssimple::keypair();
            Self {
                secret_key: sk,
                public_key: pk,
            }
        }

        pub fn verifier(&self) -> SlhDsaSha2_256sVerifier {
            SlhDsaSha2_256sVerifier {
                public_key: self.public_key,
            }
        }
    }

    impl Signer for SlhDsaSha2_256sSigner {
        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::SlhDsaSha2_256s
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            let sig = sphincssha2256ssimple::detached_sign(message, &self.secret_key);
            Ok(sig.as_bytes().to_vec())
        }

        fn public_key(&self) -> Result<Vec<u8>> {
            Ok(self.public_key.as_bytes().to_vec())
        }
    }

    pub struct SlhDsaSha2_256sVerifier {
        public_key: sphincssha2256ssimple::PublicKey,
    }

    impl SlhDsaSha2_256sVerifier {
        pub fn from_public_key(bytes: &[u8]) -> Result<Self> {
            let pk = sphincssha2256ssimple::PublicKey::from_bytes(bytes).map_err(|_| {
                NivritError::Crypto("invalid slh-dsa-sha2-256s public key length".into())
            })?;
            Ok(Self { public_key: pk })
        }
    }

    impl Verifier for SlhDsaSha2_256sVerifier {
        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
            let sig =
                sphincssha2256ssimple::DetachedSignature::from_bytes(signature).map_err(|_| {
                    NivritError::Crypto("invalid slh-dsa-sha2-256s signature length".into())
                })?;
            sphincssha2256ssimple::verify_detached_signature(&sig, message, &self.public_key)
                .map_err(|e| slh_verify_error("slh-dsa-sha2-256s", e))
        }
    }
}

#[cfg(feature = "pq-signatures")]
pub use slh_dsa_impl::{
    SlhDsaSha2_128sSigner, SlhDsaSha2_128sVerifier, SlhDsaSha2_256sSigner, SlhDsaSha2_256sVerifier,
};

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
            SignatureAlgorithm::SlhDsaSha2_128s,
            SignatureAlgorithm::SlhDsaSha2_256s,
        ] {
            assert_eq!(alg.as_str().parse::<SignatureAlgorithm>().unwrap(), alg);
        }
    }

    #[test]
    fn unknown_algorithm_errors() {
        assert!("rsa-pss".parse::<SignatureAlgorithm>().is_err());
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

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn slh_dsa_sha2_128s_sign_verify_roundtrip() {
        let signer = SlhDsaSha2_128sSigner::generate();
        let verifier = signer.verifier();
        let msg = b"hello sphincs+";
        let sig = signer.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn slh_dsa_sha2_128s_wrong_message_fails() {
        let signer = SlhDsaSha2_128sSigner::generate();
        let verifier = signer.verifier();
        let sig = signer.sign(b"hello").unwrap();
        assert!(verifier.verify(b"world", &sig).is_err());
    }

    #[test]
    #[cfg(feature = "pq-signatures")]
    fn slh_dsa_sha2_256s_sign_verify_roundtrip() {
        let signer = SlhDsaSha2_256sSigner::generate();
        let verifier = signer.verifier();
        let msg = b"hello sphincs+ 256s";
        let sig = signer.sign(msg).unwrap();
        verifier.verify(msg, &sig).unwrap();
    }
}
