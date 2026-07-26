//! Async wrappers for CPU-bound cryptography.
//!
//! Argon2id is deliberately expensive: 64 MiB of memory and hundreds of
//! milliseconds of CPU per call. Running that directly inside an `async fn`
//! parks a Tokio worker thread for the whole duration, so a handful of
//! concurrent logins can stall every other request on the runtime — including
//! the `/ready` healthcheck, which then triggers a restart.
//!
//! Every hashing call in the API goes through this module so the work lands on
//! the blocking pool instead.

use nivrit_core::{NivritError, Result};

/// Run a CPU-bound closure on the blocking pool.
///
/// A `JoinError` here means the task panicked or the runtime is shutting down;
/// both are internal faults, never client-actionable.
async fn blocking<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| NivritError::Internal(format!("hashing task failed: {e}")))?
}

/// Hash a client-supplied credential (an authentication hash) for storage.
pub async fn hash_credential(credential: String) -> Result<String> {
    blocking(move || nivrit_auth::hash_password(&credential)).await
}

/// Verify a client-supplied credential against a stored hash.
pub async fn verify_credential(credential: String, hash: String) -> Result<bool> {
    blocking(move || nivrit_auth::verify_password(&credential, &hash)).await
}
