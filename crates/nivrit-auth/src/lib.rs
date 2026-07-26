//! Server-side authentication primitives.
//!
//! Note what is *not* here: master-password handling. Under Nivrit's
//! split-derivation scheme the server never receives a password. Clients derive
//! an opaque authentication hash (`nivrit_crypto::derive_auth_hash`) and the
//! server treats it as a credential — [`CredentialHasher`] operates on that
//! hash, never on a password. Recovery-code generation and private-key wrapping
//! are likewise client-only and live in `nivrit-crypto`.
//!
//! Consequently there is no Argon2 here either; see [`credential`] for why
//! storing an already-derived credential calls for a keyed hash rather than a
//! memory-hard one.

pub mod credential;
pub mod email;
pub mod jwt;
pub mod totp;

pub use credential::CredentialHasher;
pub use email::{send_password_reset, EmailConfig};
pub use jwt::{Claims, JwtConfig};
