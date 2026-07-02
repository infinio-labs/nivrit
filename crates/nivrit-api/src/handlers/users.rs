use axum::{
    extract::{Query, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::NivritError;
use nivrit_db::queries;
use serde::{Deserialize, Serialize};

use crate::{
    auth::CurrentUser,
    error::ApiError,
    handlers::authz::{require_project_member, require_role},
    state::AppState,
};
use nivrit_core::Role;

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Deserialize)]
pub struct PublicKeyQuery {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub id: String,
    pub email: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct MyProjectResponse {
    pub project_id: String,
    pub role: String,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    pub project_key_algorithm: String,
}

/// Look up a user's public key by email.
pub async fn get_public_key(
    State(state): State<AppState>,
    CurrentUser(_user): CurrentUser,
    Query(query): Query<PublicKeyQuery>,
) -> ApiResult<Json<PublicKeyResponse>> {
    if query.email.is_empty() {
        return Err(NivritError::Validation("email required".into()).into());
    }

    let row = queries::get_user_public_key_by_email(&state.db, &query.email).await?;

    Ok(Json(PublicKeyResponse {
        id: row.id.to_string(),
        email: row.email,
        public_key: STANDARD.encode(&row.public_key),
    }))
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    pub private_key_algorithm: String,
}

/// Return the current user's profile, including the encrypted private key blob
/// so a password-authenticated CLI can decrypt it locally.
pub async fn get_me(CurrentUser(user): CurrentUser) -> ApiResult<Json<MeResponse>> {
    Ok(Json(MeResponse {
        id: user.id.to_string(),
        email: user.email,
        name: user.name,
        public_key: STANDARD.encode(&user.public_key),
        encrypted_private_key: STANDARD.encode(&user.encrypted_private_key),
        private_key_nonce: STANDARD.encode(&user.private_key_nonce),
        private_key_algorithm: user.private_key_algorithm,
    }))
}

/// List the current user's project memberships, including the encrypted project
/// key blobs needed for client-side recovery after login.
pub async fn get_my_projects(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> ApiResult<Json<Vec<MyProjectResponse>>> {
    let rows = queries::list_user_projects(&state.db, user.id).await?;

    let responses = rows
        .into_iter()
        .map(|row| MyProjectResponse {
            project_id: row.project_id.to_string(),
            role: row.role,
            encrypted_project_key: STANDARD.encode(&row.encrypted_project_key),
            project_key_nonce: STANDARD.encode(&row.project_key_nonce),
            project_key_algorithm: row.project_key_algorithm,
        })
        .collect();

    Ok(Json(responses))
}

#[derive(Debug, Serialize)]
pub struct MyOrgResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
}

/// List organizations the current user is a member of.
pub async fn get_my_orgs(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
) -> ApiResult<Json<Vec<MyOrgResponse>>> {
    let rows = queries::list_user_orgs(&state.db, user.id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| MyOrgResponse {
                id: row.id.to_string(),
                name: row.name,
                slug: row.slug,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub private_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_algorithm: String,
    /// Re-encrypted project keys for each membership the user wants to rotate.
    pub project_keys: Vec<RotatedProjectKey>,
}

#[derive(Debug, Deserialize)]
pub struct RotatedProjectKey {
    pub project_id: uuid::Uuid,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub project_key_algorithm: String,
}

fn default_private_key_algorithm() -> String {
    "aes256gcm-v1".into()
}

/// Rotate the current user's key pair.
///
/// The client generates a new hybrid key pair, re-encrypts each project key
/// from the old private key to the new public key, and uploads the new public
/// key plus the rotated membership keys. This is a client-driven rotation: the
/// server never sees plaintext private keys.
pub async fn rotate_key(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<RotateKeyRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let public_key = STANDARD
        .decode(&req.public_key)
        .map_err(|e| NivritError::Validation(format!("invalid public_key: {}", e)))?;
    let encrypted_private_key = STANDARD
        .decode(&req.encrypted_private_key)
        .map_err(|e| NivritError::Validation(format!("invalid encrypted_private_key: {}", e)))?;
    let private_key_nonce = STANDARD
        .decode(&req.private_key_nonce)
        .map_err(|e| NivritError::Validation(format!("invalid private_key_nonce: {}", e)))?;

    queries::update_user_keys(
        &state.db,
        user.id,
        &public_key,
        &encrypted_private_key,
        &private_key_nonce,
        &req.private_key_algorithm,
    )
    .await?;

    for key in req.project_keys {
        let membership = require_project_member(&state.db, key.project_id, user.id).await?;
        require_role(&membership, Role::Member)?;

        let encrypted_project_key = STANDARD.decode(&key.encrypted_project_key).map_err(|e| {
            NivritError::Validation(format!("invalid encrypted_project_key: {}", e))
        })?;
        let project_key_nonce = STANDARD
            .decode(&key.project_key_nonce)
            .map_err(|e| NivritError::Validation(format!("invalid project_key_nonce: {}", e)))?;

        queries::update_project_member_key(
            &state.db,
            key.project_id,
            user.id,
            &encrypted_project_key,
            &project_key_nonce,
            &key.project_key_algorithm,
        )
        .await?;
    }

    Ok(Json(serde_json::json!({"rotated": true})))
}
