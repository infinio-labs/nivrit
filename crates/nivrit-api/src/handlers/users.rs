use axum::{
    extract::{Query, State},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::NivritError;
use nivrit_db::queries;
use serde::{Deserialize, Serialize};

use uuid::Uuid;

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
    /// The project this lookup is for. Scopes the endpoint to "inviting
    /// someone I have the right to invite" instead of "any authenticated user
    /// can resolve any email to an account", which is otherwise a free
    /// enumeration oracle over the whole user table.
    pub project_id: Uuid,
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

/// Look up a user's public key by email, for inviting them to a project.
///
/// Requires Member+ in `project_id` - the same bar `invite_member` itself
/// enforces - so this cannot be used as a bare "does this email exist"
/// lookup by an arbitrary authenticated account with no relationship to
/// either the caller or the project the lookup is supposedly for.
pub async fn get_public_key(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Query(query): Query<PublicKeyQuery>,
) -> ApiResult<Json<PublicKeyResponse>> {
    if query.email.is_empty() {
        return Err(NivritError::Validation("email required".into()).into());
    }

    let membership = require_project_member(&state.db, query.project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

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
    /// The private key re-wrapped under the (unchanged) recovery key. Required:
    /// rotation changes the private key, so a stale recovery blob would restore
    /// the old one at reset time.
    pub encrypted_private_key_recovery: String,
    pub private_key_recovery_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub private_key_recovery_algorithm: String,
    /// Credential for the newly issued recovery code. Rotation replaces the
    /// recovery code along with the key pair, since the old code wraps a
    /// private key that no longer exists.
    pub recovery_auth_hash: String,
    /// Re-encrypted project keys for each membership the user wants to rotate.
    pub project_keys: Vec<RotatedProjectKey>,
}

#[derive(Debug, Deserialize)]
pub struct RotatedProjectKey {
    pub project_id: uuid::Uuid,
    /// Which project-key version this wrap is for (ADR 0008). A user who has
    /// been through a project rotation holds more than one version per
    /// project and must re-wrap every one of them here, not just the
    /// current one -- otherwise older versions stay encapsulated to the
    /// personal key pair this call is replacing, and become unrecoverable.
    #[serde(default = "default_project_key_version")]
    pub version: i32,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    #[serde(default = "default_private_key_algorithm")]
    pub project_key_algorithm: String,
}

fn default_project_key_version() -> i32 {
    1
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
    let encrypted_private_key_recovery = STANDARD
        .decode(&req.encrypted_private_key_recovery)
        .map_err(|e| {
            NivritError::Validation(format!("invalid encrypted_private_key_recovery: {}", e))
        })?;
    let private_key_recovery_nonce =
        STANDARD
            .decode(&req.private_key_recovery_nonce)
            .map_err(|e| {
                NivritError::Validation(format!("invalid private_key_recovery_nonce: {}", e))
            })?;

    let recovery_auth_hash = STANDARD
        .decode(&req.recovery_auth_hash)
        .map_err(|e| NivritError::Validation(format!("invalid recovery_auth_hash: {}", e)))?;
    if recovery_auth_hash.len() != 32 {
        return Err(NivritError::Validation("recovery_auth_hash must be 32 bytes".into()).into());
    }
    let recovery_code_hash = state
        .credentials
        .hash(&STANDARD.encode(&recovery_auth_hash));

    // Decode everything before touching the database so a malformed entry
    // cannot abort the transaction halfway.
    // (project_id, version, encrypted_project_key, project_key_nonce, project_key_algorithm)
    type DecodedProjectKey = (Uuid, i32, Vec<u8>, Vec<u8>, String);
    let decoded: Vec<DecodedProjectKey> = req
        .project_keys
        .iter()
        .map(|key| {
            let encrypted = STANDARD.decode(&key.encrypted_project_key).map_err(|e| {
                NivritError::Validation(format!("invalid encrypted_project_key: {}", e))
            })?;
            let nonce = STANDARD.decode(&key.project_key_nonce).map_err(|e| {
                NivritError::Validation(format!("invalid project_key_nonce: {}", e))
            })?;
            Ok((
                key.project_id,
                key.version,
                encrypted,
                nonce,
                key.project_key_algorithm.clone(),
            ))
        })
        .collect::<Result<Vec<_>, NivritError>>()?;

    let project_keys: Vec<queries::RotatedProjectKey<'_>> = decoded
        .iter()
        .map(
            |(project_id, version, encrypted, nonce, algorithm)| queries::RotatedProjectKey {
                project_id: *project_id,
                version: *version,
                encrypted_project_key: encrypted,
                project_key_nonce: nonce,
                project_key_algorithm: algorithm,
            },
        )
        .collect();

    queries::rotate_user_keys(
        &state.db,
        user.id,
        &queries::UserKeyRotation {
            public_key: &public_key,
            encrypted_private_key: &encrypted_private_key,
            private_key_nonce: &private_key_nonce,
            private_key_algorithm: &req.private_key_algorithm,
            encrypted_private_key_recovery: &encrypted_private_key_recovery,
            private_key_recovery_nonce: &private_key_recovery_nonce,
            private_key_recovery_algorithm: &req.private_key_recovery_algorithm,
            recovery_code_hash: &recovery_code_hash,
        },
        &project_keys,
    )
    .await?;

    Ok(Json(serde_json::json!({"rotated": true})))
}
