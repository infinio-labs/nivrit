use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    // Operational defaults live in code (not baked into the image) so a published
    // image carries no environment, yet still runs out of the box.
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Log output format: "pretty" (human, default) or "json" (structured, for
    /// log aggregators in production).
    #[serde(default = "default_log_format")]
    pub log_format: String,
    pub auth_secret: String,
    #[serde(default = "default_token_expiry")]
    pub token_expiry_seconds: i64,
    /// Path to the TLS certificate chain (PEM). If omitted, the server runs plain HTTP.
    pub tls_cert_path: Option<String>,
    /// Path to the TLS private key (PEM). Required when `tls_cert_path` is set.
    pub tls_key_path: Option<String>,
    /// Allowed CORS origin. If omitted, CORS allows any origin (development only).
    pub cors_origin: Option<String>,
    /// Set when the API sits behind a reverse proxy you control (the bundled
    /// nginx, a load balancer). Rate limiting then keys on the last
    /// `X-Forwarded-For` hop instead of the socket peer, which would otherwise
    /// be the proxy for every request and collapse all users into one bucket.
    ///
    /// Off by default: honouring a client-supplied header on a directly exposed
    /// server would let any caller forge their way past the limiter.
    #[serde(default)]
    pub trusted_proxy: bool,
    /// Base64-encoded 32-byte seed for the ML-DSA-65 audit-log signing key.
    /// Required unless `audit_signing_disabled` is explicitly set -- see
    /// `validate()`.
    pub signing_key_seed: Option<String>,
    /// Explicit opt-out of audit-log signing when `signing_key_seed` is unset.
    /// Exists so running without signing is a decision visible in config, not
    /// a default nobody chose.
    #[serde(default)]
    pub audit_signing_disabled: bool,

    // OAuth
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    /// Frontend URL that the OAuth provider redirects back to.
    #[serde(default = "default_oauth_redirect_url")]
    pub oauth_redirect_url: String,

    // Email (password reset)
    #[serde(default = "default_email_mode")]
    pub email_mode: String,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<String>,
    pub smtp_pass: Option<String>,
    pub smtp_from: Option<String>,

    // TOTP secret encryption
    pub totp_encryption_key: Option<String>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config: Config = Figment::new()
            .merge(Toml::file("nivrit.toml").nested())
            .merge(Env::raw().only(&["DATABASE_URL"]))
            .merge(Env::prefixed("NIVRIT_").split("__").lowercase(true))
            .extract()?;
        config.validate()?;
        Ok(config)
    }

    /// Fail fast on insecure configuration before the server accepts traffic.
    /// A weak or placeholder JWT secret means forgeable auth tokens for every
    /// account, so this is a hard error, not a warning.
    fn validate(&self) -> anyhow::Result<()> {
        if self.auth_secret.len() < 32 {
            anyhow::bail!(
                "NIVRIT_AUTH_SECRET must be at least 32 bytes (got {})",
                self.auth_secret.len()
            );
        }
        if is_placeholder(&self.auth_secret) {
            anyhow::bail!(
                "NIVRIT_AUTH_SECRET is still the example/placeholder value; generate a real secret"
            );
        }
        if let Some(key) = &self.totp_encryption_key {
            if is_placeholder(key) {
                anyhow::bail!("NIVRIT_TOTP_ENCRYPTION_KEY is still the example/placeholder value; generate a real key");
            }
        }
        match &self.signing_key_seed {
            Some(seed) if is_placeholder(seed) => {
                anyhow::bail!(
                    "NIVRIT_SIGNING_KEY_SEED is still the example/placeholder value; generate a real seed"
                );
            }
            None if !self.audit_signing_disabled => {
                // An unset seed used to mean "signatures silently disabled" --
                // a deployment could run indefinitely writing unsigned audit
                // rows with nobody deciding that on purpose. Require an
                // explicit choice instead: set a seed, or say out loud that
                // you don't want signing.
                anyhow::bail!(
                    "NIVRIT_SIGNING_KEY_SEED is not set. Either generate one (e.g. `openssl rand -base64 32`) \
                     or set NIVRIT_AUDIT_SIGNING_DISABLED=true to explicitly run without signed audit logs."
                );
            }
            _ => {}
        }
        Ok(())
    }
}

fn default_host() -> String {
    // Bind all interfaces by default: the server is meant to receive traffic and
    // typically runs in a container. Override with NIVRIT_HOST.
    "0.0.0.0".into()
}

fn default_port() -> u16 {
    4000
}

fn default_log_level() -> String {
    "info".into()
}

fn default_log_format() -> String {
    "pretty".into()
}

fn default_token_expiry() -> i64 {
    3600
}

fn default_oauth_redirect_url() -> String {
    "http://localhost:8080/oauth/callback".into()
}

fn default_email_mode() -> String {
    "log".into()
}

/// Reject the well-known `.env.example` defaults so a deployment can't ship with them.
fn is_placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.contains("change-this") || v.contains("change-me")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config {
            database_url: "postgres://x".into(),
            host: "127.0.0.1".into(),
            port: 4000,
            log_level: "info".into(),
            log_format: "pretty".into(),
            auth_secret: "x".repeat(32),
            token_expiry_seconds: 3600,
            tls_cert_path: None,
            tls_key_path: None,
            cors_origin: None,
            trusted_proxy: false,
            signing_key_seed: None,
            audit_signing_disabled: true,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_url: default_oauth_redirect_url(),
            email_mode: "log".into(),
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_pass: None,
            smtp_from: None,
            totp_encryption_key: None,
        }
    }

    #[test]
    fn accepts_strong_secret() {
        assert!(base().validate().is_ok());
    }

    #[test]
    fn rejects_short_secret() {
        let mut c = base();
        c.auth_secret = "tooshort".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_placeholder_secret() {
        let mut c = base();
        c.auth_secret = "change-this-to-a-random-32-byte-secret-key".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_placeholder_totp_key() {
        let mut c = base();
        c.totp_encryption_key = Some("change-me-to-a-base64-32-byte-key".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_missing_signing_seed_without_explicit_opt_out() {
        let mut c = base();
        c.audit_signing_disabled = false;
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_explicit_audit_signing_opt_out() {
        let mut c = base();
        c.audit_signing_disabled = true;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn accepts_real_signing_seed() {
        let mut c = base();
        c.audit_signing_disabled = false;
        c.signing_key_seed = Some("a-real-looking-base64-seed-value".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_placeholder_signing_seed() {
        let mut c = base();
        c.signing_key_seed = Some("change-this-signing-key-seed".into());
        assert!(c.validate().is_err());
    }
}
