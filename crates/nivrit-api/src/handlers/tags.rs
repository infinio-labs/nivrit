use axum::{extract::State, Json};
use nivrit_core::{NivritError, Role};
use nivrit_db::queries;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::CurrentUser,
    error::ApiError,
    handlers::authz::{require_project_member, require_role},
    state::AppState,
};

type ApiResult<T> = std::result::Result<T, ApiError>;

// Tags are plaintext labels (name + color) on secrets — pure metadata, no
// secret value involved, so no E2EE needed (like folder/environment names).

#[derive(Debug, Serialize)]
pub struct TagResponse {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub color: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTagRequest {
    pub name: String,
    pub color: Option<String>,
}

fn to_response(row: nivrit_db::models::TagRow) -> TagResponse {
    TagResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        name: row.name,
        color: row.color,
    }
}

pub async fn list_tags(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Vec<TagResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows = queries::list_tags(&state.db, project_id).await?;
    Ok(Json(rows.into_iter().map(to_response).collect()))
}

pub async fn create_tag(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<CreateTagRequest>,
) -> ApiResult<Json<TagResponse>> {
    if req.name.is_empty() {
        return Err(NivritError::Validation("name required".into()).into());
    }

    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    let color = req.color.as_deref().unwrap_or("#888888");
    let row = queries::create_tag(&state.db, project_id, &req.name, color).await?;
    Ok(Json(to_response(row)))
}

pub async fn delete_tag(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, tag_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    queries::delete_tag(&state.db, project_id, tag_id).await?;
    Ok(Json(serde_json::json!({"deleted": true, "id": tag_id})))
}

// --- Attaching tags to a secret (resolved by key within an env/folder scope) ---

#[derive(Debug, Deserialize)]
pub struct SecretTagQuery {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct AttachTagRequest {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub tag_id: Uuid,
}

pub async fn list_secret_tags(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    axum::extract::Query(query): axum::extract::Query<SecretTagQuery>,
) -> ApiResult<Json<Vec<TagResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let secret =
        queries::get_secret(&state.db, project_id, query.environment_id, query.folder_id, &key)
            .await?;
    let rows = queries::list_secret_tags(&state.db, secret.id).await?;
    Ok(Json(rows.into_iter().map(to_response).collect()))
}

pub async fn attach_secret_tag(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key)): axum::extract::Path<(Uuid, String)>,
    Json(req): Json<AttachTagRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    let secret =
        queries::get_secret(&state.db, project_id, req.environment_id, req.folder_id, &key).await?;
    queries::attach_secret_tag(&state.db, secret.id, req.tag_id).await?;
    Ok(Json(serde_json::json!({"attached": true, "tag_id": req.tag_id})))
}

pub async fn detach_secret_tag(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, key, tag_id)): axum::extract::Path<(Uuid, String, Uuid)>,
    axum::extract::Query(query): axum::extract::Query<SecretTagQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    let secret =
        queries::get_secret(&state.db, project_id, query.environment_id, query.folder_id, &key)
            .await?;
    queries::detach_secret_tag(&state.db, secret.id, tag_id).await?;
    Ok(Json(serde_json::json!({"detached": true, "tag_id": tag_id})))
}
