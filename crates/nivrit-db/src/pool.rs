use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

#[derive(Clone)]
pub struct DbPool(pub PgPool);

impl DbPool {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;

        Ok(Self(pool))
    }

    pub fn inner(&self) -> &PgPool {
        &self.0
    }

    /// Readiness check: confirm the database is reachable.
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.0).await?;
        Ok(())
    }
}
