use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{Duration, Utc};
use nivrit_auth::send_password_reset;
use nivrit_core::NivritError;
use nivrit_db::queries;
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::LazyLock;

use crate::{
    cpu::{hash_credential, verify_credential},
    error::ApiError,
    state::AppState,
};

type ApiResult<T> = std::result::Result<T, ApiError>;

/// Length of an Argon2id-derived client credential.
const CREDENTIAL_LEN: usize = 32;
/// AES-256-GCM nonce length used for the stored TOTP blob.
const TOTP_NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length.
const AES_GCM_TAG_LEN: usize = 16;

fn default_private_key_algorithm() -> String {
    "aes256gcm-v1".into()
}

/// A real Argon2 hash used to equalize login timing on the account-missing and
/// credential-less (OAuth-only) paths, so response time can't reveal whether an
/// account exists. Computed once.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    nivrit_auth::hash_password("nivrit-timing-equalization-dummy-credential")
        .expect("dummy credential hash must compute")
});

fn dummy_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.as_str()
}

/// Registration payload.
///
/// Note that there is no `password` field. The client derives everything below
/// locally (see `nivrit_web_crypto::generate_registration_material`): the server
/// receives an opaque `auth_hash`, an opaque `recovery_auth_hash`, and
/// ciphertext it cannot open. The master password and the recovery code never
/// leave the client, so a hostile or compromised server has nothing to capture.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    /// Base64 `Argon2id(password, salt=H(email))`. Opaque credential.
    pub auth_hash: String,
    pub name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_algorithm: String,
    /// Base64 `Argon2id(recovery_code, salt=H(email))`. Opaque credential.
    pub recovery_auth_hash: String,
    /// The private key, wrapped under the client-derived recovery key.
    pub encrypted_private_key_recovery: String,
    pub private_key_recovery_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_recovery_algorithm: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

/// Registration succeeds with an ordinary auth response. The recovery code is
/// *not* returned: the client generated it and is responsible for showing it to
/// the user exactly once. The server never saw it.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    pub private_key_algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    /// Base64 client-derived authentication hash. See [`RegisterRequest`].
    pub auth_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum LoginResult {
    Success(AuthResponse),
    MfaRequired { temp_token: String },
}

#[derive(Debug, Deserialize)]
pub struct MfaLoginRequest {
    pub temp_token: String,
    pub code: String,
}

// ---------------------------------------------------------------------------
// Password auth
// ---------------------------------------------------------------------------

pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    // Registration is unauthenticated and each call costs a 64 MiB Argon2id
    // hash, so it is throttled per source IP like login is. Without this an
    // anonymous caller can exhaust server memory with a loop.
    let rate_key = format!("register|{}", client_ip(&state, &headers, &addr));
    if !state.login_rate_limiter.allow(&rate_key).await? {
        return Err(NivritError::Forbidden.into());
    }
    state.login_rate_limiter.record_attempt(&rate_key).await?;

    if req.email.trim().is_empty() {
        return Err(NivritError::Validation("email required".into()).into());
    }

    // The credential is a fixed-width derived hash, not a password, so the
    // length rule that used to enforce password strength now lives on the
    // client. What the server checks is that this really is a 32-byte hash.
    let auth_hash = decode_credential(&req.auth_hash, "auth_hash")?;
    let recovery_auth_hash = decode_credential(&req.recovery_auth_hash, "recovery_auth_hash")?;

    let public_key = decode_b64(&req.public_key, "public_key")?;
    let encrypted_private_key = decode_b64(&req.encrypted_private_key, "encrypted_private_key")?;
    let private_key_nonce = decode_b64(&req.private_key_nonce, "private_key_nonce")?;
    let encrypted_private_key_recovery = decode_b64(
        &req.encrypted_private_key_recovery,
        "encrypted_private_key_recovery",
    )?;
    let private_key_recovery_nonce = decode_b64(
        &req.private_key_recovery_nonce,
        "private_key_recovery_nonce",
    )?;

    // Both credentials are stored as Argon2id hashes so that a database leak
    // yields nothing replayable.
    let password_hash = hash_credential(auth_hash).await?;
    let recovery_code_hash = hash_credential(recovery_auth_hash).await?;

    let row = queries::create_user_with_recovery(
        &state.db,
        &req.email,
        req.name.as_deref(),
        Some(&password_hash),
        &public_key,
        &encrypted_private_key,
        &private_key_nonce,
        &req.private_key_algorithm,
        Some(&recovery_code_hash),
        Some(&encrypted_private_key_recovery),
        Some(&private_key_recovery_nonce),
        Some(&req.private_key_recovery_algorithm),
        None,
    )
    .await?;

    let token = state.jwt.sign(row.id, row.email.clone())?;

    Ok(Json(RegisterResponse {
        token,
        user: user_row_to_response(&row),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResult>> {
    // Two independent buckets. The per-IP bucket stops one host from grinding
    // through candidates. The per-email bucket is what stops a distributed
    // attack: without it, rotating source IPs gives an attacker unlimited
    // guesses against a single account, because every new IP is a fresh key.
    let ip = client_ip(&state, &headers, &addr);
    let ip_key = format!("login-ip|{ip}");
    let email_key = format!("login-email|{}", req.email.trim().to_lowercase());
    if !state.login_rate_limiter.allow(&ip_key).await?
        || !state.login_rate_limiter.allow(&email_key).await?
    {
        return Err(NivritError::Forbidden.into());
    }

    let auth_hash = decode_credential(&req.auth_hash, "auth_hash")?;

    let row = queries::get_user_by_email(&state.db, &req.email).await;

    // Always perform exactly one Argon2 verify, even when the account is missing
    // or credential-less, so timing doesn't leak account existence.
    let credential_ok = match row {
        Ok(ref user) => match user.password_hash.as_deref() {
            Some(hash) => verify_credential(auth_hash, hash.to_string()).await?,
            None => {
                let _ = verify_credential(auth_hash, dummy_hash().to_string()).await;
                false
            }
        },
        Err(_) => {
            let _ = verify_credential(auth_hash, dummy_hash().to_string()).await;
            false
        }
    };

    if !credential_ok {
        // Best-effort: a DB hiccup here must not change the auth outcome.
        let _ = state.login_rate_limiter.record_failure(&ip_key).await;
        let _ = state.login_rate_limiter.record_failure(&email_key).await;
        return Err(NivritError::Unauthorized.into());
    }

    // credential_ok == true guarantees the lookup succeeded.
    let row = row?;
    let _ = state.login_rate_limiter.record_success(&ip_key).await;
    let _ = state.login_rate_limiter.record_success(&email_key).await;

    if row.totp_enabled {
        let temp_token = state
            .jwt
            .sign_with_mfa(row.id, row.email.clone(), true)
            .map_err(|e| NivritError::Internal(e.to_string()))?;
        return Ok(Json(LoginResult::MfaRequired { temp_token }));
    }

    let token = state.jwt.sign(row.id, row.email.clone())?;
    Ok(Json(LoginResult::Success(AuthResponse {
        token,
        user: user_row_to_response(&row),
    })))
}

pub async fn login_totp(
    State(state): State<AppState>,
    Json(req): Json<MfaLoginRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let claims = state
        .jwt
        .verify(&req.temp_token)
        .map_err(|_| NivritError::Unauthorized)?;
    if !claims.mfa_pending {
        return Err(NivritError::Unauthorized.into());
    }

    let row = queries::get_user_by_id(&state.db, claims.sub).await?;
    if !row.totp_enabled {
        return Err(NivritError::Unauthorized.into());
    }

    let Some(ref totp_blob) = row.totp_secret_encrypted else {
        return Err(NivritError::Internal("TOTP secret missing".into()).into());
    };
    if totp_blob.len() < 12 + 16 {
        return Err(NivritError::Internal("invalid TOTP blob".into()).into());
    }
    let (nonce, ciphertext) = totp_blob.split_at(12);
    let Some(totp_key) = state.totp_encryption_key else {
        return Err(NivritError::Internal("TOTP encryption key not configured".into()).into());
    };
    let secret = nivrit_auth::totp::decrypt_secret(ciphertext, nonce, &totp_key)
        .map_err(|_| NivritError::Internal("failed to decrypt TOTP secret".into()))?;
    let Some(step) = nivrit_auth::totp::verify_code_step(&secret, &req.code) else {
        return Err(NivritError::Unauthorized.into());
    };
    // Reject replay: a code's time step must be strictly newer than the last used.
    if let Some(last) = queries::get_totp_last_step(&state.db, row.id).await? {
        if step <= last as u64 {
            return Err(NivritError::Unauthorized.into());
        }
    }
    queries::set_totp_last_step(&state.db, row.id, step as i64).await?;

    let token = state.jwt.sign(row.id, row.email.clone())?;
    Ok(Json(AuthResponse {
        token,
        user: user_row_to_response(&row),
    }))
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OAuthAuthorizeRequest {
    pub provider: String,
}

#[derive(Debug, Serialize)]
pub struct OAuthAuthorizeResponse {
    pub url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackRequest {
    pub provider: String,
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum OAuthCallbackResult {
    Existing(AuthResponse),
    SetupRequired {
        /// Provider and (display-only) profile fields to prefill the setup form.
        provider: String,
        email: String,
        name: Option<String>,
        /// Server-signed token sealing the proven OAuth identity. The setup step
        /// trusts only this token, not any client-supplied identity fields.
        setup_token: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct OAuthSetupRequest {
    /// Signed identity token issued by `oauth_callback`. Replaces the previously
    /// client-supplied provider/provider_user_id/email/name, which were trusted
    /// without proof and allowed account pre-hijacking.
    pub setup_token: String,
    /// Base64 client-derived authentication hash for the chosen master
    /// password. The password itself never reaches the server.
    pub auth_hash: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_algorithm: String,
    pub recovery_auth_hash: String,
    pub encrypted_private_key_recovery: String,
    pub private_key_recovery_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_recovery_algorithm: String,
}

pub async fn oauth_authorize(
    State(state): State<AppState>,
    Json(req): Json<OAuthAuthorizeRequest>,
) -> ApiResult<Json<OAuthAuthorizeResponse>> {
    let state_param = crate::oauth_token::issue_state(&state.config.auth_secret, &req.provider)?;
    let redirect_uri = &state.config.oauth_redirect_url;
    let url = match req.provider.as_str() {
        "google" => google_authorize_url(
            state.config.google_client_id.as_deref(),
            redirect_uri,
            &state_param,
        )?,
        "github" => github_authorize_url(
            state.config.github_client_id.as_deref(),
            redirect_uri,
            &state_param,
        )?,
        _ => return Err(NivritError::Validation("unsupported OAuth provider".into()).into()),
    };
    Ok(Json(OAuthAuthorizeResponse {
        url,
        state: state_param,
    }))
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Json(req): Json<OAuthCallbackRequest>,
) -> ApiResult<Json<OAuthCallbackResult>> {
    // Reject any state we did not sign (CSRF / injected code+state).
    crate::oauth_token::verify_state(&state.config.auth_secret, &req.state, &req.provider)?;

    let profile = match req.provider.as_str() {
        "google" => exchange_google_code(&state, &req.code).await?,
        "github" => exchange_github_code(&state, &req.code).await?,
        _ => return Err(NivritError::Validation("unsupported OAuth provider".into()).into()),
    };

    if profile.provider_user_id.is_empty() {
        return Err(NivritError::Internal("OAuth provider returned no user id".into()).into());
    }

    if let Some(row) =
        queries::get_user_by_oauth(&state.db, &req.provider, &profile.provider_user_id).await?
    {
        let token = state.jwt.sign(row.id, row.email.clone())?;
        return Ok(Json(OAuthCallbackResult::Existing(AuthResponse {
            token,
            user: user_row_to_response(&row),
        })));
    }

    // Seal the proven identity so setup cannot be called with a forged one.
    let setup_token = crate::oauth_token::issue_setup(
        &state.config.auth_secret,
        &req.provider,
        &profile.provider_user_id,
        &profile.email,
        profile.name.as_deref(),
    )?;

    Ok(Json(OAuthCallbackResult::SetupRequired {
        provider: req.provider,
        email: profile.email,
        name: profile.name,
        setup_token,
    }))
}

pub async fn oauth_setup(
    State(state): State<AppState>,
    Json(req): Json<OAuthSetupRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    // Trust only the server-signed identity, never client-supplied fields.
    let identity = crate::oauth_token::verify_setup(&state.config.auth_secret, &req.setup_token)?;
    if identity.email.is_empty() {
        return Err(NivritError::Validation("OAuth identity has no email".into()).into());
    }

    let auth_hash = decode_credential(&req.auth_hash, "auth_hash")?;
    let recovery_auth_hash = decode_credential(&req.recovery_auth_hash, "recovery_auth_hash")?;

    let public_key = decode_b64(&req.public_key, "public_key")?;
    let encrypted_private_key = decode_b64(&req.encrypted_private_key, "encrypted_private_key")?;
    let private_key_nonce = decode_b64(&req.private_key_nonce, "private_key_nonce")?;
    let encrypted_private_key_recovery = decode_b64(
        &req.encrypted_private_key_recovery,
        "encrypted_private_key_recovery",
    )?;
    let private_key_recovery_nonce = decode_b64(
        &req.private_key_recovery_nonce,
        "private_key_recovery_nonce",
    )?;

    // OAuth users still set a master password client-side — it wraps their
    // private key — so they do get a stored credential, unlike before.
    let password_hash = hash_credential(auth_hash).await?;
    let recovery_code_hash = hash_credential(recovery_auth_hash).await?;

    let row = queries::create_user_with_recovery(
        &state.db,
        &identity.email,
        identity.name.as_deref(),
        Some(&password_hash),
        &public_key,
        &encrypted_private_key,
        &private_key_nonce,
        &req.private_key_algorithm,
        Some(&recovery_code_hash),
        Some(&encrypted_private_key_recovery),
        Some(&private_key_recovery_nonce),
        Some(&req.private_key_recovery_algorithm),
        None,
    )
    .await?;

    queries::create_oauth_account(
        &state.db,
        row.id,
        &identity.provider,
        &identity.provider_user_id,
    )
    .await?;

    let token = state.jwt.sign(row.id, row.email.clone())?;
    Ok(Json(RegisterResponse {
        token,
        user: user_row_to_response(&row),
    }))
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

/// Step 1 of reset: prove possession of the recovery code and receive the
/// recovery blob. The blob is ciphertext the server cannot open — only the
/// holder of the actual recovery code can, and that code never leaves the
/// client.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordBeginRequest {
    pub token: String,
    pub recovery_auth_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordBeginResponse {
    pub encrypted_private_key_recovery: String,
    pub private_key_recovery_nonce: String,
    pub private_key_recovery_algorithm: String,
}

/// Step 2 of reset: the client has decrypted its private key with the recovery
/// key and re-wrapped it under the new password. It uploads the new credential
/// and the new ciphertext.
///
/// The recovery blob itself is unchanged by a password reset: it wraps the
/// private key under the *recovery* key, which does not depend on the password.
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub recovery_auth_hash: String,
    pub new_auth_hash: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_algorithm: String,
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Ok(row) = queries::get_user_by_email(&state.db, &req.email).await else {
        // Always return success so emails can't be enumerated.
        return Ok(Json(serde_json::json!({ "sent": true })));
    };

    let raw_token = generate_secure_token();
    let token_hash = hash_token(&raw_token);
    let expires_at = Utc::now() + Duration::minutes(15);
    queries::create_password_reset_token(&state.db, row.id, &token_hash, expires_at).await?;

    let reset_link = format!(
        "{}?token={}",
        state
            .config
            .oauth_redirect_url
            .replace("/oauth/callback", "/reset-password"),
        raw_token
    );
    // Best-effort email; failures are logged but not exposed.
    if let Err(e) = send_password_reset(&req.email, &reset_link, &state.email_config).await {
        tracing::error!("failed to send password reset email: {}", e);
    }

    Ok(Json(serde_json::json!({ "sent": true })))
}

pub async fn verify_reset_token(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ApiResult<Json<serde_json::Value>> {
    let token = params
        .get("token")
        .ok_or_else(|| NivritError::Validation("token required".into()))?;
    let token_hash = hash_token(token);
    let row = queries::get_password_reset_token_by_hash(&state.db, &token_hash).await?;
    if row.used_at.is_some() || row.expires_at < Utc::now() {
        return Err(NivritError::Unauthorized.into());
    }
    Ok(Json(serde_json::json!({ "valid": true })))
}

/// Validate a reset token and the supplied recovery credential together.
///
/// Returns the user row on success. Every failure path returns `Unauthorized`
/// so this cannot be used to probe which of the two was wrong.
async fn authorize_reset(
    state: &AppState,
    token: &str,
    recovery_auth_hash: &str,
) -> ApiResult<(nivrit_db::models::UserRow, uuid::Uuid)> {
    let recovery_auth_hash = decode_credential(recovery_auth_hash, "recovery_auth_hash")?;

    let token_hash = hash_token(token);
    let token_row = queries::get_password_reset_token_by_hash(&state.db, &token_hash)
        .await
        .map_err(|_| NivritError::Unauthorized)?;
    if token_row.used_at.is_some() || token_row.expires_at < Utc::now() {
        return Err(NivritError::Unauthorized.into());
    }

    let user = queries::get_user_by_id(&state.db, token_row.user_id).await?;
    let stored_hash = user
        .recovery_code_hash
        .as_deref()
        .ok_or(NivritError::Unauthorized)?;

    if !verify_credential(recovery_auth_hash, stored_hash.to_string()).await? {
        return Err(NivritError::Unauthorized.into());
    }

    Ok((user, token_row.id))
}

pub async fn reset_password_begin(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordBeginRequest>,
) -> ApiResult<Json<ResetPasswordBeginResponse>> {
    // Guessing the recovery credential is the only way past this endpoint, so
    // throttle it the same way login is throttled.
    let rate_key = format!("reset|{}", client_ip(&state, &headers, &addr));
    if !state.login_rate_limiter.allow(&rate_key).await? {
        return Err(NivritError::Forbidden.into());
    }

    let (user, _) = match authorize_reset(&state, &req.token, &req.recovery_auth_hash).await {
        Ok(v) => v,
        Err(e) => {
            let _ = state.login_rate_limiter.record_failure(&rate_key).await;
            return Err(e);
        }
    };
    let _ = state.login_rate_limiter.record_success(&rate_key).await;

    let (Some(ciphertext), Some(nonce)) = (
        user.encrypted_private_key_recovery.as_ref(),
        user.private_key_recovery_nonce.as_ref(),
    ) else {
        return Err(NivritError::Internal("recovery material missing".into()).into());
    };

    Ok(Json(ResetPasswordBeginResponse {
        encrypted_private_key_recovery: STANDARD.encode(ciphertext),
        private_key_recovery_nonce: STANDARD.encode(nonce),
        private_key_recovery_algorithm: user
            .private_key_recovery_algorithm
            .clone()
            .unwrap_or_else(default_private_key_algorithm),
    }))
}

pub async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ResetPasswordRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let rate_key = format!("reset|{}", client_ip(&state, &headers, &addr));
    if !state.login_rate_limiter.allow(&rate_key).await? {
        return Err(NivritError::Forbidden.into());
    }

    let (user, token_id) = match authorize_reset(&state, &req.token, &req.recovery_auth_hash).await
    {
        Ok(v) => v,
        Err(e) => {
            let _ = state.login_rate_limiter.record_failure(&rate_key).await;
            return Err(e);
        }
    };
    let _ = state.login_rate_limiter.record_success(&rate_key).await;

    let new_auth_hash = decode_credential(&req.new_auth_hash, "new_auth_hash")?;
    let new_encrypted_private_key =
        decode_b64(&req.encrypted_private_key, "encrypted_private_key")?;
    let new_private_key_nonce = decode_b64(&req.private_key_nonce, "private_key_nonce")?;

    let new_password_hash = hash_credential(new_auth_hash).await?;

    queries::update_user_password_and_keys(
        &state.db,
        user.id,
        &new_password_hash,
        &new_encrypted_private_key,
        &new_private_key_nonce,
        &req.private_key_algorithm,
    )
    .await?;

    queries::mark_password_reset_token_used(&state.db, token_id).await?;

    let token = state.jwt.sign(user.id, user.email.clone())?;
    Ok(Json(AuthResponse {
        token,
        user: user_row_to_response(&user),
    }))
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

use crate::auth::CurrentUser;

#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub uri: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpDisableRequest {
    /// Client-derived authentication hash, same value used at login.
    pub auth_hash: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpSetupRequest {
    /// Required only when re-enrolling over an existing TOTP secret.
    #[serde(default)]
    pub auth_hash: Option<String>,
}

pub async fn setup_totp(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<TotpSetupRequest>,
) -> ApiResult<Json<TotpSetupResponse>> {
    let Some(totp_key) = state.totp_encryption_key else {
        return Err(NivritError::Internal("TOTP encryption key not configured".into()).into());
    };

    // Re-enrolling replaces the existing second factor, so it must cost more
    // than a stolen session token. Without this, anyone holding a hijacked JWT
    // or a leaked PAT can silently swap in their own authenticator.
    let row = queries::get_user_by_id(&state.db, user.id).await?;
    if row.totp_enabled {
        let Some(auth_hash) = req.auth_hash.as_deref() else {
            return Err(NivritError::Validation(
                "auth_hash required to replace an existing TOTP secret".into(),
            )
            .into());
        };
        let auth_hash = decode_credential(auth_hash, "auth_hash")?;
        let Some(stored) = row.password_hash.as_deref() else {
            return Err(NivritError::Forbidden.into());
        };
        if !verify_credential(auth_hash, stored.to_string()).await? {
            return Err(NivritError::Unauthorized.into());
        }
    }

    let secret = nivrit_auth::totp::generate_secret();
    let uri = nivrit_auth::totp::provisioning_uri(&secret, &user.email)?;

    let blob = nivrit_auth::totp::encrypt_secret(&secret, &totp_key)
        .map_err(|_| NivritError::Internal("failed to encrypt TOTP secret".into()))?;
    let mut encrypted = Vec::with_capacity(blob.1.len() + blob.0.len());
    encrypted.extend_from_slice(&blob.1);
    encrypted.extend_from_slice(&blob.0);

    queries::store_totp_secret(&state.db, user.id, &encrypted).await?;
    Ok(Json(TotpSetupResponse { secret, uri }))
}

pub async fn verify_totp(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<TotpVerifyRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(totp_key) = state.totp_encryption_key else {
        return Err(NivritError::Internal("TOTP encryption key not configured".into()).into());
    };
    let Some(blob) = queries::get_totp_secret(&state.db, user.id).await? else {
        return Err(NivritError::Validation("TOTP not set up".into()).into());
    };
    if blob.len() < 12 + 16 {
        return Err(NivritError::Internal("invalid TOTP blob".into()).into());
    }
    let (nonce, ciphertext) = blob.split_at(12);
    let secret = nivrit_auth::totp::decrypt_secret(ciphertext, nonce, &totp_key)
        .map_err(|_| NivritError::Internal("failed to decrypt TOTP secret".into()))?;
    if !nivrit_auth::totp::verify_code(&secret, &req.code) {
        return Err(NivritError::Validation("invalid TOTP code".into()).into());
    }
    queries::enable_totp(&state.db, user.id).await?;
    Ok(Json(serde_json::json!({ "enabled": true })))
}

pub async fn disable_totp(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<TotpDisableRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let row = queries::get_user_by_id(&state.db, user.id).await?;
    let Some(password_hash) = row.password_hash.as_deref() else {
        return Err(NivritError::Forbidden.into());
    };
    let auth_hash = decode_credential(&req.auth_hash, "auth_hash")?;
    if !verify_credential(auth_hash, password_hash.to_string()).await? {
        return Err(NivritError::Unauthorized.into());
    }

    let Some(totp_key) = state.totp_encryption_key else {
        return Err(NivritError::Internal("TOTP encryption key not configured".into()).into());
    };
    let Some(blob) = queries::get_totp_secret(&state.db, user.id).await? else {
        return Err(NivritError::Validation("TOTP not set up".into()).into());
    };
    // `split_at` panics when the slice is shorter than the split point, which in
    // a handler means a killed task rather than an error response. The two
    // sibling call sites guard this; so does this one now.
    if blob.len() < TOTP_NONCE_LEN + AES_GCM_TAG_LEN {
        return Err(NivritError::Internal("invalid TOTP blob".into()).into());
    }
    let (nonce, ciphertext) = blob.split_at(TOTP_NONCE_LEN);
    let secret = nivrit_auth::totp::decrypt_secret(ciphertext, nonce, &totp_key)
        .map_err(|_| NivritError::Internal("failed to decrypt TOTP secret".into()))?;
    if !nivrit_auth::totp::verify_code(&secret, &req.code) {
        return Err(NivritError::Validation("invalid TOTP code".into()).into());
    }

    queries::disable_totp(&state.db, user.id).await?;
    Ok(Json(serde_json::json!({ "disabled": true })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn user_row_to_response(row: &nivrit_db::models::UserRow) -> UserResponse {
    UserResponse {
        id: row.id.to_string(),
        email: row.email.clone(),
        name: row.name.clone(),
        public_key: STANDARD.encode(&row.public_key),
        encrypted_private_key: STANDARD.encode(&row.encrypted_private_key),
        private_key_nonce: STANDARD.encode(&row.private_key_nonce),
        private_key_algorithm: row.private_key_algorithm.clone(),
    }
}

fn decode_b64(input: &str, field: &str) -> ApiResult<Vec<u8>> {
    STANDARD
        .decode(input)
        .map_err(|e| NivritError::Validation(format!("invalid {}: {}", field, e)).into())
}

/// Decode a client-derived credential and check it is the right shape.
///
/// Credentials are always a 32-byte Argon2id output. Rejecting anything else
/// keeps a caller from sending a short or empty string and turning the stored
/// hash into something cheap to attack.
fn decode_credential(input: &str, field: &str) -> ApiResult<String> {
    let bytes = decode_b64(input, field)?;
    if bytes.len() != CREDENTIAL_LEN {
        return Err(
            NivritError::Validation(format!("{field} must be {CREDENTIAL_LEN} bytes")).into(),
        );
    }
    // Re-encode canonically so that two encodings of the same bytes cannot
    // produce two different stored hashes.
    Ok(STANDARD.encode(&bytes))
}

/// Resolve the client address for rate limiting.
///
/// When the API sits behind the bundled nginx (or any reverse proxy) the socket
/// peer is the proxy, which would collapse every user into a single rate-limit
/// bucket. `NIVRIT_TRUSTED_PROXY` opts into reading the last hop from
/// `X-Forwarded-For` instead. It is off by default: trusting that header from an
/// arbitrary client would let anyone forge their way around the limiter.
fn client_ip(state: &AppState, headers: &HeaderMap, addr: &SocketAddr) -> String {
    if state.config.trusted_proxy {
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

fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("operating-system RNG failure");
    STANDARD.encode(bytes)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    STANDARD.encode(hasher.finalize())
}

fn google_authorize_url(
    client_id: Option<&str>,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<String> {
    let client_id = client_id
        .ok_or_else(|| NivritError::Validation("Google client ID not configured".into()))?;
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=online",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state)
    );
    Ok(url)
}

fn github_authorize_url(
    client_id: Option<&str>,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<String> {
    let client_id = client_id
        .ok_or_else(|| NivritError::Validation("GitHub client ID not configured".into()))?;
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state)
    );
    Ok(url)
}

#[derive(Debug)]
struct OAuthProfile {
    provider_user_id: String,
    email: String,
    name: Option<String>,
}

async fn exchange_google_code(state: &AppState, code: &str) -> ApiResult<OAuthProfile> {
    let client_id = state
        .config
        .google_client_id
        .as_deref()
        .ok_or_else(|| NivritError::Validation("Google client ID not configured".into()))?;
    let client_secret = state
        .config
        .google_client_secret
        .as_deref()
        .ok_or_else(|| NivritError::Validation("Google client secret not configured".into()))?;

    let params = [
        ("code", code),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("redirect_uri", &state.config.oauth_redirect_url),
        ("grant_type", "authorization_code"),
    ];

    let client = &state.http_client;
    let token_res: serde_json::Value = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| NivritError::Internal(format!("Google token exchange failed: {}", e)))?
        .json()
        .await
        .map_err(|e| NivritError::Internal(format!("Google token response invalid: {}", e)))?;

    let access_token = token_res["access_token"]
        .as_str()
        .ok_or_else(|| NivritError::Internal("Google access_token missing".into()))?;

    let profile: serde_json::Value = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| NivritError::Internal(format!("Google profile request failed: {}", e)))?
        .json()
        .await
        .map_err(|e| NivritError::Internal(format!("Google profile response invalid: {}", e)))?;

    Ok(OAuthProfile {
        provider_user_id: profile["id"].as_str().unwrap_or("").to_string(),
        email: profile["email"].as_str().unwrap_or("").to_string(),
        name: profile["name"].as_str().map(|s| s.to_string()),
    })
}

async fn exchange_github_code(state: &AppState, code: &str) -> ApiResult<OAuthProfile> {
    let client_id = state
        .config
        .github_client_id
        .as_deref()
        .ok_or_else(|| NivritError::Validation("GitHub client ID not configured".into()))?;
    let client_secret = state
        .config
        .github_client_secret
        .as_deref()
        .ok_or_else(|| NivritError::Validation("GitHub client secret not configured".into()))?;

    let client = &state.http_client;
    let token_res: serde_json::Value = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", &state.config.oauth_redirect_url),
        ])
        .send()
        .await
        .map_err(|e| NivritError::Internal(format!("GitHub token exchange failed: {}", e)))?
        .json()
        .await
        .map_err(|e| NivritError::Internal(format!("GitHub token response invalid: {}", e)))?;

    let access_token = token_res["access_token"]
        .as_str()
        .ok_or_else(|| NivritError::Internal("GitHub access_token missing".into()))?;

    let profile: serde_json::Value = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "nivrit")
        .send()
        .await
        .map_err(|e| NivritError::Internal(format!("GitHub profile request failed: {}", e)))?
        .json()
        .await
        .map_err(|e| NivritError::Internal(format!("GitHub profile response invalid: {}", e)))?;

    let provider_user_id = profile["id"]
        .as_i64()
        .map(|id| id.to_string())
        .unwrap_or_default();
    let name = profile["name"].as_str().map(|s| s.to_string());

    let email = if let Some(email) = profile["email"].as_str() {
        email.to_string()
    } else {
        let emails: Vec<serde_json::Value> = client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "nivrit")
            .send()
            .await
            .map_err(|e| NivritError::Internal(format!("GitHub emails request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| NivritError::Internal(format!("GitHub emails response invalid: {}", e)))?;
        emails
            .iter()
            .find(|e| e["primary"].as_bool().unwrap_or(false))
            .and_then(|e| e["email"].as_str())
            .or_else(|| emails.first().and_then(|e| e["email"].as_str()))
            .unwrap_or("")
            .to_string()
    };

    Ok(OAuthProfile {
        provider_user_id,
        email,
        name,
    })
}
