use axum::http::HeaderMap;
use nivrit_auth::{CredentialHasher, EmailConfig, JwtConfig};
use nivrit_db::DbPool;
use std::net::SocketAddr;

use crate::{config::Config, rate_limit::LoginRateLimiter, signing::SignatureService};

const MAX_LOGIN_ATTEMPTS: usize = 5;
const LOGIN_WINDOW_SECONDS: u64 = 900; // 15 minutes
const LOGIN_LOCKOUT_SECONDS: u64 = 900; // 15 minutes

/// IP-scoped buckets sit behind NAT, CGNAT, and corporate proxies shared by
/// many unrelated users, so a threshold sized for "one attacker" collectively
/// punishes everyone behind that address. The per-identifier bucket (email,
/// user id) is the real defense against credential stuffing -- it can't be
/// evaded by rotating source IPs -- so the IP bucket only needs to be tight
/// enough to slow a single host grinding through candidates, not tight enough
/// to double as the primary control. Kept deliberately more permissive than
/// `MAX_LOGIN_ATTEMPTS`.
const MAX_LOGIN_ATTEMPTS_PER_IP: usize = 30;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub jwt: JwtConfig,
    /// Hashes the opaque credentials clients send in place of passwords.
    pub credentials: CredentialHasher,
    pub login_rate_limiter: LoginRateLimiter,
    /// Same mechanism as `login_rate_limiter`, more permissive thresholds --
    /// use this for IP-scoped bucket keys paired with an identifier-scoped
    /// bucket on `login_rate_limiter`, so a shared address doesn't lock out
    /// every unrelated user behind it. See `MAX_LOGIN_ATTEMPTS_PER_IP`.
    pub login_rate_limiter_ip: LoginRateLimiter,
    pub signature_service: Option<SignatureService>,
    pub email_config: EmailConfig,
    pub totp_encryption_key: Option<[u8; 32]>,
    /// Shared client for outbound OAuth calls. Has connect/request timeouts so a
    /// hung provider can't pin a request worker indefinitely.
    pub http_client: reqwest::Client,
    pub config: Config,
}

impl AppState {
    /// Resolve the client address for rate limiting.
    ///
    /// When the API sits behind the bundled nginx (or any reverse proxy) the socket
    /// peer is the proxy, which would collapse every user into a single rate-limit
    /// bucket. `NIVRIT_TRUSTED_PROXY` opts into reading the last hop from
    /// `X-Forwarded-For` instead. It is off by default: trusting that header from an
    /// arbitrary client would let anyone forge their way around the limiter.
    pub fn client_ip(&self, headers: &HeaderMap, addr: &SocketAddr) -> String {
        if self.config.trusted_proxy {
            // Take the last entry: earlier ones are client-supplied and forgeable,
            // the final hop is the one our own proxy appended.
            if let Some(last) = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                return last.to_string();
            }
        }
        addr.ip().to_string()
    }

    pub async fn from_config(config: &Config) -> anyhow::Result<Self> {
        let db = DbPool::connect(&config.database_url).await?;
        // Config::validate() already requires either a seed or an explicit
        // audit_signing_disabled=true, so reaching `None` here means the
        // operator chose that, not that they forgot to set anything.
        let signature_service = match config.signing_key_seed.as_deref() {
            Some(seed) => Some(SignatureService::from_seed_b64(seed)?),
            None => {
                tracing::warn!(
                    "NIVRIT_AUDIT_SIGNING_DISABLED=true; audit-log signatures are disabled"
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
        let login_rate_limiter_ip = LoginRateLimiter::new(
            db.clone(),
            MAX_LOGIN_ATTEMPTS_PER_IP,
            std::time::Duration::from_secs(LOGIN_WINDOW_SECONDS),
            std::time::Duration::from_secs(LOGIN_LOCKOUT_SECONDS),
        );

        Ok(Self {
            db,
            credentials: CredentialHasher::new(&config.auth_secret),
            jwt: JwtConfig {
                secret: config.auth_secret.clone(),
                expiry_seconds: config.token_expiry_seconds,
            },
            login_rate_limiter,
            login_rate_limiter_ip,
            signature_service,
            email_config,
            totp_encryption_key,
            http_client,
            config: config.clone(),
        })
    }
}
