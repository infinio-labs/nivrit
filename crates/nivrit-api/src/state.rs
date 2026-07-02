use nivrit_auth::{EmailConfig, JwtConfig};
use nivrit_db::DbPool;

use crate::{config::Config, rate_limit::LoginRateLimiter, signing::SignatureService};

const MAX_LOGIN_ATTEMPTS: usize = 5;
const LOGIN_WINDOW_SECONDS: u64 = 900; // 15 minutes
const LOGIN_LOCKOUT_SECONDS: u64 = 900; // 15 minutes

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub jwt: JwtConfig,
    pub login_rate_limiter: LoginRateLimiter,
    pub signature_service: Option<SignatureService>,
    pub email_config: EmailConfig,
    pub totp_encryption_key: Option<[u8; 32]>,
    pub recovery_code_pepper: Option<String>,
    /// Shared client for outbound OAuth calls. Has connect/request timeouts so a
    /// hung provider can't pin a request worker indefinitely.
    pub http_client: reqwest::Client,
    pub config: Config,
}

impl AppState {
    pub async fn from_config(config: &Config) -> anyhow::Result<Self> {
        let db = DbPool::connect(&config.database_url).await?;
        let signature_service = match config.signing_key_seed.as_deref() {
            Some(seed) => Some(SignatureService::from_seed_b64(seed)?),
            None => {
                tracing::warn!(
                    "NIVRIT_SIGNING_KEY_SEED is not set; audit-log signatures are disabled"
                );
                None
            }
        };

        let email_config = EmailConfig::from_env(
            &config.email_mode,
            config.smtp_host.clone(),
            config.smtp_port,
            config.smtp_user.clone(),
            config.smtp_pass.clone(),
            config.smtp_from.clone(),
        )?;

        let totp_encryption_key = config
            .totp_encryption_key
            .as_deref()
            .map(nivrit_auth::totp::decode_server_key)
            .transpose()?;

        let http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let login_rate_limiter = LoginRateLimiter::new(
            db.clone(),
            MAX_LOGIN_ATTEMPTS,
            std::time::Duration::from_secs(LOGIN_WINDOW_SECONDS),
            std::time::Duration::from_secs(LOGIN_LOCKOUT_SECONDS),
        );

        Ok(Self {
            db,
            jwt: JwtConfig {
                secret: config.auth_secret.clone(),
                expiry_seconds: config.token_expiry_seconds,
            },
            login_rate_limiter,
            signature_service,
            email_config,
            totp_encryption_key,
            recovery_code_pepper: config.recovery_code_pepper.clone(),
            http_client,
            config: config.clone(),
        })
    }
}
