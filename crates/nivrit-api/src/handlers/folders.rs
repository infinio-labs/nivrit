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

// Folders are organizational metadata (name/path), not secrets — like
// environment names, they are stored in plaintext and need no E2EE.

#[derive(Debug, Serialize)]
pub struct FolderResponse {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateFolderRequest {
    pub environment_id: Uuid,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ListFoldersQuery {
    pub environment_id: Uuid,
}

fn to_response(row: nivrit_db::models::FolderRow) -> FolderResponse {
    FolderResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        environment_id: row.environment_id.to_string(),
        name: row.name,
        path: row.path,
    }
}

pub async fn list_folders(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<ListFoldersQuery>,
) -> ApiResult<Json<Vec<FolderResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows = queries::list_folders(&state.db, project_id, query.environment_id).await?;
    Ok(Json(rows.into_iter().map(to_response).collect()))
}

pub async fn create_folder(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<CreateFolderRequest>,
) -> ApiResult<Json<FolderResponse>> {
    if req.name.is_empty() || req.path.is_empty() {
        return Err(NivritError::Validation("name and path required".into()).into());
    }

    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    let row =
        queries::create_folder(&state.db, project_id, req.environment_id, &req.name, &req.path)
            .await?;
    Ok(Json(to_response(row)))
}

pub async fn delete_folder(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, folder_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    queries::delete_folder(&state.db, project_id, folder_id).await?;
    Ok(Json(serde_json::json!({"deleted": true, "id": folder_id})))
}
