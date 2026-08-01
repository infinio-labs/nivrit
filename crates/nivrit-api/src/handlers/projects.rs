use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nivrit_core::{NivritError, Role};
use nivrit_db::queries;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::CurrentUser,
    error::ApiError,
    handlers::authz::{require_org_member, require_org_role, require_project_member, require_role},
    state::AppState,
};

type ApiResult<T> = std::result::Result<T, ApiError>;

fn default_project_key_algorithm() -> String {
    "aes256gcm-v1".into()
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub org_id: Uuid,
    pub name: String,
    pub slug: String,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    #[serde(default = "default_project_key_algorithm")]
    pub project_key_algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateEnvironmentRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Serialize)]
pub struct ProjectResponse {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Serialize)]
pub struct EnvironmentResponse {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub slug: String,
}

pub async fn create_project(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    if req.name.is_empty() || req.slug.is_empty() {
        return Err(NivritError::Validation("name and slug required".into()).into());
    }

    // Org membership alone is not enough: it can come from being invited to a
    // single project (as an org Viewer), not from being trusted with the org.
    // Creating a project - and becoming its Admin - requires at least Member.
    let org_membership = require_org_member(&state.db, req.org_id, user.id).await?;
    require_org_role(&org_membership, Role::Member)?;

    let encrypted_project_key = STANDARD
        .decode(&req.encrypted_project_key)
        .map_err(|e| NivritError::Validation(format!("invalid encrypted_project_key: {}", e)))?;
    let project_key_nonce = STANDARD
        .decode(&req.project_key_nonce)
        .map_err(|e| NivritError::Validation(format!("invalid project_key_nonce: {}", e)))?;

    let row = queries::create_project(&state.db, req.org_id, &req.name, &req.slug).await?;
    queries::add_project_member(
        &state.db,
        row.id,
        user.id,
        Role::Admin,
        &encrypted_project_key,
        &project_key_nonce,
        &req.project_key_algorithm,
    )
    .await?;
    // Mints the project's key version 1 (ADR 0008). Same bytes as the
    // membership row above -- `add_project_member` is the legacy "current
    // key" cache older clients still read, this is the versioned history a
    // rotation-aware client needs.
    queries::mint_initial_project_key_version(
        &state.db,
        row.id,
        user.id,
        &encrypted_project_key,
        &project_key_nonce,
        &req.project_key_algorithm,
    )
    .await?;

    Ok(Json(ProjectResponse {
        id: row.id.to_string(),
        org_id: row.org_id.to_string(),
        name: row.name,
        slug: row.slug,
    }))
}

pub async fn list_environments(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Vec<EnvironmentResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows = queries::list_environments(&state.db, project_id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| EnvironmentResponse {
                id: row.id.to_string(),
                project_id: row.project_id.to_string(),
                name: row.name,
                slug: row.slug,
            })
            .collect(),
    ))
}

pub async fn create_environment(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<CreateEnvironmentRequest>,
) -> ApiResult<Json<EnvironmentResponse>> {
    if req.name.is_empty() || req.slug.is_empty() {
        return Err(NivritError::Validation("name and slug required".into()).into());
    }

    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    queries::create_environment(&state.db, project_id, &req.name, &req.slug).await?;

    let env = queries::get_environment(&state.db, project_id, &req.slug).await?;

    Ok(Json(EnvironmentResponse {
        id: env.id.to_string(),
        project_id: env.project_id.to_string(),
        name: env.name,
        slug: env.slug,
    }))
}

#[derive(Debug, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: Role,
    pub encrypted_project_key: nivrit_crypto::EncapsulatedProjectKey,
}

#[derive(Debug, Serialize)]
pub struct ProjectMemberResponse {
    pub user_id: String,
    pub project_id: String,
    pub role: String,
}

/// Invite a user to a project by encrypting the project key to their public key.
///
/// The caller supplies a hybrid-encapsulated project key; the server validates
/// that the caller is a project admin and stores the ciphertext for the invitee.
pub async fn invite_member(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<InviteMemberRequest>,
) -> ApiResult<Json<ProjectMemberResponse>> {
    if req.email.is_empty() {
        return Err(NivritError::Validation("email required".into()).into());
    }

    // Only project admins may invite members.
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Admin)?;

    // Look up the invitee by email.
    let invitee = queries::get_user_public_key_by_email(&state.db, &req.email).await?;

    // Serialize the encapsulated key as the stored project-key blob.
    let encrypted_project_key = serde_json::to_vec(&req.encrypted_project_key).map_err(|e| {
        NivritError::Internal(format!("failed to serialize encrypted project key: {e}"))
    })?;

    queries::add_project_member(
        &state.db,
        project_id,
        invitee.id,
        req.role,
        &encrypted_project_key,
        &[],
        &req.encrypted_project_key.suite,
    )
    .await?;
    // Grants the invitee the project's *current latest* key version (ADR
    // 0008), not a fixed version 1 -- an invite after a rotation must not
    // hand out an old, superseded key.
    queries::grant_latest_project_key_version(
        &state.db,
        project_id,
        invitee.id,
        &encrypted_project_key,
        &[],
        &req.encrypted_project_key.suite,
    )
    .await?;

    // Ensure the invitee can also see the parent organization in the UI. Grant
    // the lowest org role only — a project admin must not be able to mint org
    // admins/members through a project invite. (No-op if already a member.)
    let project = queries::get_project_by_id(&state.db, project_id).await?;
    let _ = queries::add_org_member(&state.db, project.org_id, invitee.id, Role::Viewer).await;

    Ok(Json(ProjectMemberResponse {
        user_id: invitee.id.to_string(),
        project_id: project_id.to_string(),
        role: role_as_str(req.role).to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct ProjectMemberKeyResponse {
    pub user_id: String,
    pub public_key: String,
}

/// The roster a client needs before it can rotate: every current member and
/// the public key a new grant must be encapsulated to. Anyone in the project
/// can list it (needed to *see* who'd be affected), but only an Admin can
/// actually call `rotate_key` below.
pub async fn list_members(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Vec<ProjectMemberKeyResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows = queries::list_current_project_members_with_keys(&state.db, project_id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| ProjectMemberKeyResponse {
                user_id: row.user_id.to_string(),
                public_key: STANDARD.encode(&row.public_key),
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize)]
pub struct ProjectKeyVersionResponse {
    pub version: i32,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    pub project_key_algorithm: String,
}

/// Every project-key version the caller has been granted, oldest first --
/// what a rotation-aware client needs to decrypt the project's full secret
/// history, not just what's current (ADR 0008).
pub async fn list_my_key_versions(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Vec<ProjectKeyVersionResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows = queries::list_project_key_grants_for_user(&state.db, project_id, user.id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| ProjectKeyVersionResponse {
                version: row.version,
                encrypted_project_key: STANDARD.encode(&row.encrypted_project_key),
                project_key_nonce: STANDARD.encode(&row.project_key_nonce),
                project_key_algorithm: row.project_key_algorithm,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct RotateProjectKeyGrantRequest {
    pub user_id: Uuid,
    pub encrypted_project_key: String,
    pub project_key_nonce: String,
    pub project_key_algorithm: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateProjectKeyRequest {
    pub grants: Vec<RotateProjectKeyGrantRequest>,
}

#[derive(Debug, Serialize)]
pub struct RotateProjectKeyResponse {
    pub version: i32,
}

/// Mint the next project-key version and grant it to exactly the caller's
/// supplied roster (ADR 0008). The caller (any Admin) is responsible for
/// generating the new key client-side, encapsulating it to every current
/// member's public key (see `list_members` above), and never generating the
/// server-side -- this server never sees plaintext key material, only already
/// -encapsulated grants. `queries::rotate_project_key` independently verifies
/// the grant list covers exactly the project's real current membership before
/// committing, so a stale or tampered roster is rejected rather than silently
/// locking someone out or leaving someone ungranted.
///
/// No existing secret is touched. Older ciphertext stays under whichever
/// version encrypted it; only new writes use the version minted here.
pub async fn rotate_key(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<RotateProjectKeyRequest>,
) -> ApiResult<Json<RotateProjectKeyResponse>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Admin)?;

    if req.grants.is_empty() {
        return Err(NivritError::Validation("grants required".into()).into());
    }

    let mut decoded = Vec::with_capacity(req.grants.len());
    for grant in &req.grants {
        let encrypted_project_key = STANDARD
            .decode(&grant.encrypted_project_key)
            .map_err(|e| NivritError::Validation(format!("invalid encrypted_project_key: {e}")))?;
        let project_key_nonce = STANDARD
            .decode(&grant.project_key_nonce)
            .map_err(|e| NivritError::Validation(format!("invalid project_key_nonce: {e}")))?;
        decoded.push((
            grant.user_id,
            encrypted_project_key,
            project_key_nonce,
            grant.project_key_algorithm.clone(),
        ));
    }

    let grants: Vec<queries::RotationGrant> = decoded
        .iter()
        .map(
            |(user_id, encrypted_project_key, project_key_nonce, project_key_algorithm)| {
                queries::RotationGrant {
                    user_id: *user_id,
                    encrypted_project_key,
                    project_key_nonce,
                    project_key_algorithm,
                }
            },
        )
        .collect();

    let pkv = queries::rotate_project_key(&state.db, project_id, user.id, &grants).await?;

    Ok(Json(RotateProjectKeyResponse {
        version: pkv.version,
    }))
}

#[cfg(test)]
fn role_from_str(s: &str) -> Result<Role, NivritError> {
    match s {
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        "viewer" => Ok(Role::Viewer),
        _ => Err(NivritError::Validation(format!("invalid role: {s}"))),
    }
}

fn role_as_str(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Member => "member",
        Role::Viewer => "viewer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_from_str_parses_known_roles() {
        assert_eq!(role_from_str("admin").unwrap(), Role::Admin);
        assert_eq!(role_from_str("member").unwrap(), Role::Member);
        assert_eq!(role_from_str("viewer").unwrap(), Role::Viewer);
    }

    #[test]
    fn role_from_str_rejects_unknown() {
        assert!(role_from_str("owner").is_err());
    }

    #[test]
    fn role_as_str_roundtrip() {
        assert_eq!(role_as_str(Role::Admin), "admin");
        assert_eq!(role_as_str(Role::Member), "member");
        assert_eq!(role_as_str(Role::Viewer), "viewer");
    }
}
