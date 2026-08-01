use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::{NivritError, Role};
use nivrit_db::queries;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{
    auth::CurrentUser,
    error::ApiError,
    handlers::authz::{require_environment_role, require_project_member},
    signing::AuditLogMessage,
    state::AppState,
};
use chrono::{DateTime, SubsecRound, Utc};

type ApiResult<T> = std::result::Result<T, ApiError>;

/// Page size when a caller does not ask for one.
const DEFAULT_PAGE_LIMIT: i64 = 100;
/// Server-enforced ceiling. A caller asking for more gets this instead, so one
/// request can never pull an unbounded result set into memory.
const MAX_PAGE_LIMIT: i64 = 1000;

/// Clamp caller-supplied paging into a range the server is willing to serve.
fn page(limit: Option<i64>, offset: Option<i64>) -> (i64, i64) {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT);
    let offset = offset.unwrap_or(0).max(0);
    (limit, offset)
}

fn default_algorithm() -> String {
    "aes256gcm-v1".into()
}

/// Sign and record one access-log entry, chained to its project's prior
/// entry, logging (not silently dropping) any failure to do so.
///
/// This is best-effort by design, not by accident: failing the secret
/// read/write itself because the audit table hiccuped would turn an
/// observability problem into an availability one. But "best-effort" and
/// "silent" are different things - a signed audit trail that can lose entries
/// without anyone noticing isn't one you can rely on for anything.
///
/// The chain lock is acquired first and held until the row commits, so two
/// concurrent writes for the same project can't both link to the same prior
/// entry (see `queries::begin_access_log_chain`).
#[allow(clippy::too_many_arguments)]
async fn record_access(
    state: &AppState,
    project_id: Uuid,
    environment_id: Option<Uuid>,
    secret_id: Option<Uuid>,
    user_id: Uuid,
    action: &str,
    key: &str,
    ip: &str,
    user_agent: Option<&str>,
    created_at: DateTime<Utc>,
) {
    let (mut tx, prev_hash, chain_seq) =
        match queries::begin_access_log_chain(&state.db, project_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    project_id = %project_id, action, key, error = %e,
                    "failed to open audit-log chain; this access was not logged"
                );
                return;
            }
        };

    let msg = AuditLogMessage::new(
        project_id,
        environment_id,
        user_id,
        action,
        key,
        created_at,
        prev_hash.as_deref(),
    );

    let signed = match state
        .signature_service
        .as_ref()
        .map(|svc| svc.sign_audit_log(&msg))
    {
        Some(Ok(signed)) => Some(signed),
        Some(Err(e)) => {
            // The signed audit trail is only tamper-evident if every entry is
            // actually signed. Recording unsigned and moving on turns a broken
            // signing key into a silent, permanent gap in that trail instead of
            // an alert someone can act on.
            tracing::error!(
                project_id = %project_id, action, key, error = %e,
                "failed to sign audit log entry; recording it unsigned"
            );
            None
        }
        None => None,
    };

    let entry_hash = match crate::signing::entry_hash(&msg, signed.as_ref()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(
                project_id = %project_id, action, key, error = %e,
                "failed to compute audit-log chain hash; this access was not logged"
            );
            return;
        }
    };

    let inserted = queries::insert_access_log_chained(
        &mut tx,
        project_id,
        environment_id,
        secret_id,
        user_id,
        action,
        key,
        Some(ip),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
        chain_seq,
        prev_hash.as_deref(),
        &entry_hash,
    )
    .await;

    if let Err(e) = inserted {
        tracing::error!(
            project_id = %project_id, action, key, error = %e,
            "failed to record audit log entry; this access was not logged"
        );
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::error!(
            project_id = %project_id, action, key, error = %e,
            "failed to commit audit log entry; this access was not logged"
        );
    }
}

fn default_project_key_version() -> i32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub key: String,
    pub encrypted_value: String,
    pub nonce: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Which project-key version `encrypted_value` was encrypted under (ADR
    /// 0008). Defaults to 1 so clients unaware of rotation (a project that's
    /// never been rotated has no other version to be aware of) keep working
    /// unchanged.
    #[serde(default = "default_project_key_version")]
    pub project_key_version: i32,
}

#[derive(Debug, Serialize)]
pub struct SecretResponse {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub folder_id: Option<String>,
    pub key: String,
    pub encrypted_value: String,
    pub nonce: String,
    pub algorithm: String,
    pub version: i32,
    pub project_key_version: i32,
}

pub async fn create_secret(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<CreateSecretRequest>,
) -> ApiResult<Json<SecretResponse>> {
    if req.key.is_empty() {
        return Err(NivritError::Validation("key required".into()).into());
    }

    require_environment_role(
        &state.db,
        project_id,
        req.environment_id,
        user.id,
        Role::Member,
    )
    .await?;

    let encrypted_value = STANDARD
        .decode(&req.encrypted_value)
        .map_err(|e| NivritError::Validation(format!("invalid encrypted_value: {}", e)))?;
    let nonce = STANDARD
        .decode(&req.nonce)
        .map_err(|e| NivritError::Validation(format!("invalid nonce: {}", e)))?;

    let row = queries::create_secret(
        &state.db,
        project_id,
        req.environment_id,
        req.folder_id,
        &req.key,
        &encrypted_value,
        &nonce,
        &req.algorithm,
        req.project_key_version,
    )
    .await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    record_access(
        &state,
        project_id,
        Some(req.environment_id),
        Some(row.id),
        user.id,
        "write",
        &req.key,
        &addr.ip().to_string(),
        user_agent,
        created_at,
    )
    .await;

    Ok(Json(SecretResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        environment_id: row.environment_id.to_string(),
        folder_id: row.folder_id.map(|id| id.to_string()),
        key: row.key,
        encrypted_value: STANDARD.encode(&row.encrypted_value),
        nonce: STANDARD.encode(&row.nonce),
        algorithm: row.algorithm,
        version: row.version,
        project_key_version: row.project_key_version,
    }))
}

#[derive(Debug, Deserialize)]
pub struct GetSecretQuery {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ListSecretsQuery {
    pub environment_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_secrets(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<ListSecretsQuery>,
) -> ApiResult<Json<Vec<SecretResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let (limit, offset) = page(query.limit, query.offset);
    let rows = queries::list_secrets(
        &state.db,
        project_id,
        query.environment_id,
        query.folder_id,
        limit,
        offset,
    )
    .await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    record_access(
        &state,
        project_id,
        query.environment_id,
        None,
        user.id,
        "read",
        "*",
        &addr.ip().to_string(),
        user_agent,
        created_at,
    )
    .await;

    Ok(Json(
        rows.into_iter()
            .map(|row| SecretResponse {
                id: row.id.to_string(),
                project_id: row.project_id.to_string(),
                environment_id: row.environment_id.to_string(),
                folder_id: row.folder_id.map(|id| id.to_string()),
                key: row.key,
                encrypted_value: STANDARD.encode(&row.encrypted_value),
                nonce: STANDARD.encode(&row.nonce),
                algorithm: row.algorithm,
                version: row.version,
                project_key_version: row.project_key_version,
            })
            .collect(),
    ))
}

pub async fn delete_secret(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<GetSecretQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    require_environment_role(
        &state.db,
        project_id,
        query.environment_id,
        user.id,
        Role::Member,
    )
    .await?;

    let _deleted_secret_id = queries::delete_secret(
        &state.db,
        project_id,
        query.environment_id,
        query.folder_id,
        &key,
    )
    .await?;

    // Audit the deletion without a secret_id foreign-key reference because the
    // secret row has already been removed.
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    record_access(
        &state,
        project_id,
        Some(query.environment_id),
        None,
        user.id,
        "delete",
        &key,
        &addr.ip().to_string(),
        user_agent,
        created_at,
    )
    .await;

    Ok(Json(serde_json::json!({"deleted": true, "key": key})))
}

#[derive(Debug, Serialize)]
pub struct SecretVersionResponse {
    pub version: i32,
    pub encrypted_value: String,
    pub nonce: String,
    pub algorithm: String,
    pub project_key_version: i32,
    pub created_at: DateTime<Utc>,
}

/// Version history for a secret. Returns ciphertext per version; the client
/// decrypts E2EE — the server never sees plaintext.
pub async fn list_secret_versions(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    axum::extract::Query(query): axum::extract::Query<GetSecretQuery>,
) -> ApiResult<Json<Vec<SecretVersionResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let secret = queries::get_secret(
        &state.db,
        project_id,
        query.environment_id,
        query.folder_id,
        &key,
    )
    .await?;

    let (limit, offset) = page(query.limit, query.offset);
    let versions = queries::list_secret_versions(&state.db, secret.id, limit, offset).await?;

    Ok(Json(
        versions
            .into_iter()
            .map(|v| SecretVersionResponse {
                version: v.version,
                encrypted_value: STANDARD.encode(&v.encrypted_value),
                nonce: STANDARD.encode(&v.nonce),
                algorithm: v.algorithm,
                project_key_version: v.project_key_version,
                created_at: v.created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct RestoreSecretRequest {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub version: i32,
}

/// Point-in-time recovery: restore a prior version's ciphertext as a new
/// version. Server only copies opaque bytes forward — fully E2EE-native.
pub async fn restore_secret(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RestoreSecretRequest>,
) -> ApiResult<Json<SecretResponse>> {
    require_environment_role(
        &state.db,
        project_id,
        req.environment_id,
        user.id,
        Role::Member,
    )
    .await?;

    let row = queries::restore_secret_version(
        &state.db,
        project_id,
        req.environment_id,
        req.folder_id,
        &key,
        req.version,
    )
    .await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    record_access(
        &state,
        project_id,
        Some(req.environment_id),
        Some(row.id),
        user.id,
        "write",
        &key,
        &addr.ip().to_string(),
        user_agent,
        created_at,
    )
    .await;

    Ok(Json(SecretResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        environment_id: row.environment_id.to_string(),
        folder_id: row.folder_id.map(|id| id.to_string()),
        key: row.key,
        encrypted_value: STANDARD.encode(&row.encrypted_value),
        nonce: STANDARD.encode(&row.nonce),
        algorithm: row.algorithm,
        version: row.version,
        project_key_version: row.project_key_version,
    }))
}

pub async fn get_secret(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<GetSecretQuery>,
) -> ApiResult<Json<SecretResponse>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let row = queries::get_secret(
        &state.db,
        project_id,
        query.environment_id,
        query.folder_id,
        &key,
    )
    .await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    record_access(
        &state,
        project_id,
        Some(query.environment_id),
        Some(row.id),
        user.id,
        "read",
        &key,
        &addr.ip().to_string(),
        user_agent,
        created_at,
    )
    .await;

    Ok(Json(SecretResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        environment_id: row.environment_id.to_string(),
        folder_id: row.folder_id.map(|id| id.to_string()),
        key: row.key,
        encrypted_value: STANDARD.encode(&row.encrypted_value),
        nonce: STANDARD.encode(&row.nonce),
        algorithm: row.algorithm,
        version: row.version,
        project_key_version: row.project_key_version,
    }))
}
