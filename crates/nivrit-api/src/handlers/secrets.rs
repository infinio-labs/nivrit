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
    handlers::authz::{require_project_member, require_role},
    signing::{AuditLogMessage, SignedAuditLog},
    state::AppState,
};
use chrono::{DateTime, SubsecRound, Utc};

type ApiResult<T> = std::result::Result<T, ApiError>;

fn default_algorithm() -> String {
    "aes256gcm-v1".into()
}

#[allow(clippy::too_many_arguments)]
fn build_signed_audit_log(
    state: &AppState,
    project_id: Uuid,
    environment_id: Option<Uuid>,
    user_id: Uuid,
    action: &str,
    key: &str,
    created_at: DateTime<Utc>,
) -> Option<SignedAuditLog> {
    state.signature_service.as_ref().and_then(|svc| {
        let msg =
            AuditLogMessage::new(project_id, environment_id, user_id, action, key, created_at);
        svc.sign_audit_log(&msg).ok()
    })
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

    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

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
    )
    .await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    let signed = build_signed_audit_log(
        &state,
        project_id,
        Some(req.environment_id),
        user.id,
        "write",
        &req.key,
        created_at,
    );

    let _ = queries::insert_access_log(
        &state.db,
        project_id,
        Some(req.environment_id),
        Some(row.id),
        user.id,
        "write",
        &req.key,
        Some(&addr.ip().to_string()),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
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
    }))
}

#[derive(Debug, Deserialize)]
pub struct GetSecretQuery {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ListSecretsQuery {
    pub environment_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
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

    let rows =
        queries::list_secrets(&state.db, project_id, query.environment_id, query.folder_id).await?;

    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());
    let created_at = Utc::now().trunc_subsecs(6);
    let signed = build_signed_audit_log(
        &state,
        project_id,
        query.environment_id,
        user.id,
        "read",
        "*",
        created_at,
    );

    let _ = queries::insert_access_log(
        &state.db,
        project_id,
        query.environment_id,
        None,
        user.id,
        "read",
        "*",
        Some(&addr.ip().to_string()),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
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
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

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
    let signed = build_signed_audit_log(
        &state,
        project_id,
        Some(query.environment_id),
        user.id,
        "delete",
        &key,
        created_at,
    );

    let _ = queries::insert_access_log(
        &state.db,
        project_id,
        Some(query.environment_id),
        None,
        user.id,
        "delete",
        &key,
        Some(&addr.ip().to_string()),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
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

    let versions = queries::list_secret_versions(&state.db, secret.id).await?;

    Ok(Json(
        versions
            .into_iter()
            .map(|v| SecretVersionResponse {
                version: v.version,
                encrypted_value: STANDARD.encode(&v.encrypted_value),
                nonce: STANDARD.encode(&v.nonce),
                algorithm: v.algorithm,
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
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

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
    let signed = build_signed_audit_log(
        &state,
        project_id,
        Some(req.environment_id),
        user.id,
        "write",
        &key,
        created_at,
    );

    let _ = queries::insert_access_log(
        &state.db,
        project_id,
        Some(req.environment_id),
        Some(row.id),
        user.id,
        "write",
        &key,
        Some(&addr.ip().to_string()),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
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
    let signed = build_signed_audit_log(
        &state,
        project_id,
        Some(query.environment_id),
        user.id,
        "read",
        &key,
        created_at,
    );

    let _ = queries::insert_access_log(
        &state.db,
        project_id,
        Some(query.environment_id),
        Some(row.id),
        user.id,
        "read",
        &key,
        Some(&addr.ip().to_string()),
        user_agent,
        created_at,
        signed.as_ref().map(|s| s.algorithm.as_str()),
        signed.as_ref().map(|s| s.signature.as_slice()),
        signed.as_ref().map(|s| s.public_key.as_slice()),
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
    }))
}
