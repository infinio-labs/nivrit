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

    /// Apply any pending migrations. Migrations are embedded into the binary
    /// at compile time (`sqlx::migrate!`), so a deployment never needs a
    /// separate `sqlx-cli` binary or the migration `.sql` files on disk --
    /// one binary owns both running the server and getting the schema ready
    /// for it.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.0).await?;
        Ok(())
    }
}
