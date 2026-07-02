use axum::{extract::State, Json};
use nivrit_core::{NivritError, Role};
use nivrit_db::queries;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::CurrentUser, error::ApiError, handlers::authz::require_org_member, state::AppState,
};

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Serialize)]
pub struct OrgResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
}

pub async fn create_org(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Json(req): Json<CreateOrgRequest>,
) -> ApiResult<Json<OrgResponse>> {
    if req.name.is_empty() || req.slug.is_empty() {
        return Err(NivritError::Validation("name and slug required".into()).into());
    }

    let row = queries::create_org(&state.db, &req.name, &req.slug).await?;
    queries::add_org_member(&state.db, row.id, user.id, Role::Admin).await?;

    Ok(Json(OrgResponse {
        id: row.id.to_string(),
        name: row.name,
        slug: row.slug,
    }))
}

#[derive(Debug, Serialize)]
pub struct ProjectListItem {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
}

pub async fn list_org_projects(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    axum::extract::Path(org_id): axum::extract::Path<Uuid>,
) -> ApiResult<Json<Vec<ProjectListItem>>> {
    require_org_member(&state.db, org_id, user.id).await?;

    let rows = queries::list_projects(&state.db, org_id).await?;

    Ok(Json(
        rows.into_iter()
            .map(|row| ProjectListItem {
                id: row.id.to_string(),
                org_id: row.org_id.to_string(),
                name: row.name,
                slug: row.slug,
            })
            .collect(),
    ))
}
