use axum::{extract::State, Json};
use nivrit_core::Role;
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

// Imports are metadata links only — they say "this scope pulls in that scope".
// Secret values stay E2EE; the client fetches both scopes and merges locally.

#[derive(Debug, Serialize)]
pub struct ImportResponse {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub folder_id: Option<String>,
    pub source_environment_id: String,
    pub source_folder_id: Option<String>,
    pub position: i32,
}

#[derive(Debug, Deserialize)]
pub struct CreateImportRequest {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
    pub source_environment_id: Uuid,
    pub source_folder_id: Option<Uuid>,
    #[serde(default)]
    pub position: i32,
}

#[derive(Debug, Deserialize)]
pub struct ListImportsQuery {
    pub environment_id: Uuid,
    pub folder_id: Option<Uuid>,
}

fn to_response(row: nivrit_db::models::SecretImportRow) -> ImportResponse {
    ImportResponse {
        id: row.id.to_string(),
        project_id: row.project_id.to_string(),
        environment_id: row.environment_id.to_string(),
        folder_id: row.folder_id.map(|id| id.to_string()),
        source_environment_id: row.source_environment_id.to_string(),
        source_folder_id: row.source_folder_id.map(|id| id.to_string()),
        position: row.position,
    }
}

pub async fn list_imports(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<ListImportsQuery>,
) -> ApiResult<Json<Vec<ImportResponse>>> {
    require_project_member(&state.db, project_id, user.id).await?;

    let rows =
        queries::list_secret_imports(&state.db, project_id, query.environment_id, query.folder_id)
            .await?;
    Ok(Json(rows.into_iter().map(to_response).collect()))
}

pub async fn create_import(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(project_id): axum::extract::Path<Uuid>,
    Json(req): Json<CreateImportRequest>,
) -> ApiResult<Json<ImportResponse>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    let row = queries::create_secret_import(
        &state.db,
        project_id,
        req.environment_id,
        req.folder_id,
        req.source_environment_id,
        req.source_folder_id,
        req.position,
    )
    .await?;
    Ok(Json(to_response(row)))
}

pub async fn delete_import(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path((project_id, import_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    let membership = require_project_member(&state.db, project_id, user.id).await?;
    require_role(&membership, Role::Member)?;

    queries::delete_secret_import(&state.db, project_id, import_id).await?;
    Ok(Json(serde_json::json!({"deleted": true, "id": import_id})))
}
