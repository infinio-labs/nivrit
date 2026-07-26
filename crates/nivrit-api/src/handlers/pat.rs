use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{Duration, Utc};
use nivrit_core::NivritError;
use nivrit_db::queries;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{auth::CurrentUser, error::ApiError, state::AppState};

type ApiResult<T> = std::result::Result<T, ApiError>;

const PAT_PREFIX: &str = "niv_";
const PAT_RANDOM_BYTES: usize = 32; // 64 hex chars

#[derive(Debug, Deserialize)]
pub struct CreatePatRequest {
    pub name: String,
    /// Optional TTL in days. If omitted, the token never expires.
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreatePatResponse {
    pub id: String,
    pub name: String,
    /// The raw token is returned exactly once.
    pub token: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct PatMetadataResponse {
    pub id: String,
    pub name: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_token() -> String {
    let mut bytes = vec![0u8; PAT_RANDOM_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    format!("{}{}", PAT_PREFIX, bytes_to_hex(&bytes))
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

pub async fn create_pat(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<CreatePatRequest>,
) -> ApiResult<Json<CreatePatResponse>> {
    if req.name.trim().is_empty() {
        return Err(NivritError::Validation("token name required".into()).into());
    }

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = req
        .expires_in_days
        .map(|days| Utc::now() + Duration::days(days));

    let row = queries::create_personal_access_token(
        &state.db,
        user.id,
        &req.name,
        &token_hash,
        expires_at,
    )
    .await?;

    Ok(Json(CreatePatResponse {
        id: row.id.to_string(),
        name: row.name,
        token,
        expires_at: row.expires_at.map(|d| d.to_rfc3339()),
        created_at: row.created_at.to_rfc3339(),
    }))
}

pub async fn list_pats(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> ApiResult<Json<Vec<PatMetadataResponse>>> {
    let rows = queries::list_personal_access_tokens(&state.db, user.id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| PatMetadataResponse {
                id: row.id.to_string(),
                name: row.name,
                last_used_at: row.last_used_at.map(|d| d.to_rfc3339()),
                expires_at: row.expires_at.map(|d| d.to_rfc3339()),
                revoked_at: row.revoked_at.map(|d| d.to_rfc3339()),
                created_at: row.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn revoke_pat(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Path(token_id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    queries::revoke_personal_access_token(&state.db, token_id, user.id).await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}
