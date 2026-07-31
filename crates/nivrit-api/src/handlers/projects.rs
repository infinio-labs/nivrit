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
