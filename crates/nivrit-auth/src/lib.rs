//! Server-side authentication primitives.
//!
//! Note what is *not* here: master-password handling. Under Nivrit's
//! split-derivation scheme the server never receives a password. Clients derive
//! an opaque authentication hash (`nivrit_crypto::derive_auth_hash`) and the
//! server treats it as a credential — [`hash_password`] and [`verify_password`]
//! operate on that hash, never on a password. Recovery-code generation and
//! private-key wrapping are likewise client-only and live in `nivrit-crypto`.

pub mod email;
pub mod jwt;
pub mod password;
pub mod totp;

pub use email::{send_password_reset, EmailConfig};
pub use jwt::{Claims, JwtConfig};
pub use password::{hash_password, verify_password};
