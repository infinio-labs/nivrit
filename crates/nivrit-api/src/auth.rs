use axum::{
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use nivrit_core::User;
use nivrit_db::queries;
use sha2::{Digest, Sha256};

use crate::state::AppState;

pub struct CurrentUser(pub User);

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn row_into_user(row: nivrit_db::models::UserRow) -> User {
    User {
        id: row.id,
        email: row.email,
        name: row.name,
        public_key: row.public_key,
        encrypted_private_key: row.encrypted_private_key,
        private_key_nonce: row.private_key_nonce,
        private_key_algorithm: row.private_key_algorithm,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

impl<S> FromRequestParts<S> for CurrentUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let token = bearer.token();

        // First try JWT auth (interactive sessions).
        if let Ok(claims) = state.jwt.verify(token) {
            if claims.mfa_pending {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let row = queries::get_user_by_id(&state.db, claims.sub)
                .await
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            return Ok(CurrentUser(row_into_user(row)));
        }

        // Fall back to personal access token auth (CLI / integrations).
        let token_hash = hash_token(token);
        let (pat, row) = queries::get_user_by_token_hash(&state.db, &token_hash)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        if pat.revoked_at.is_some() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if let Some(expires_at) = pat.expires_at {
            if chrono::Utc::now() > expires_at {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        // Update last_used_at asynchronously; failures are non-fatal.
        let db = state.db.clone();
        let pat_id = pat.id;
        tokio::spawn(async move {
            let _ = queries::touch_personal_access_token(&db, pat_id).await;
        });

        Ok(CurrentUser(row_into_user(row)))
    }
}
