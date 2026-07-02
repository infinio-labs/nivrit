use std::time::Duration;

use nivrit_core::Result;
use nivrit_db::{queries, DbPool};

/// Postgres-backed login rate limiter.
///
/// State lives in the `login_attempts` table, so every API instance enforces one
/// shared limit per key (`email|ip`). After `max_attempts` failures within
/// `window`, the key is locked out for `lockout`. State is cleared on success.
#[derive(Clone)]
pub struct LoginRateLimiter {
    db: DbPool,
    max_attempts: i64,
    window_secs: i64,
    lockout_secs: i64,
}

impl LoginRateLimiter {
    pub fn new(db: DbPool, max_attempts: usize, window: Duration, lockout: Duration) -> Self {
        Self {
            db,
            max_attempts: max_attempts as i64,
            window_secs: window.as_secs() as i64,
            lockout_secs: lockout.as_secs() as i64,
        }
    }

    /// Returns true if `key` is currently allowed to attempt a login.
    pub async fn allow(&self, key: &str) -> Result<bool> {
        let blocked =
            queries::login_attempt_blocked(&self.db, key, self.window_secs, self.max_attempts)
                .await?;
        Ok(!blocked)
    }

    /// Record a failed attempt for `key`.
    pub async fn record_failure(&self, key: &str) -> Result<()> {
        // Opportunistically prune stale rows so a flood of distinct keys can't
        // grow the table without bound.
        // ponytail: 1-in-50 sampling instead of a scheduled job; add a cron prune
        // if the table still grows under sustained attack.
        if rand::random::<u8>().is_multiple_of(50) {
            let _ = queries::prune_login_attempts(&self.db, self.window_secs).await;
        }
        queries::record_login_failure(
            &self.db,
            key,
            self.window_secs,
            self.max_attempts,
            self.lockout_secs,
        )
        .await
    }

    /// Clear failures on a successful login.
    pub async fn record_success(&self, key: &str) -> Result<()> {
        queries::clear_login_attempts(&self.db, key).await
    }
}
