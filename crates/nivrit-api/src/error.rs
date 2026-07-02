use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nivrit_core::NivritError;
use serde_json::json;

pub struct ApiError(NivritError);

impl From<NivritError> for ApiError {
    fn from(err: NivritError) -> Self {
        Self(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self.0 {
            // Client-actionable errors: safe to return as-is.
            NivritError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            NivritError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".into()),
            NivritError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".into()),
            NivritError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            NivritError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            // Internal failures: log the detail server-side, return a generic
            // message so DB/crypto internals never reach the client.
            NivritError::Crypto(msg) => {
                tracing::error!(target: "nivrit_api", kind = "crypto", "{msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            NivritError::Internal(msg) => {
                tracing::error!(target: "nivrit_api", kind = "internal", "{msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn not_found_maps_to_404() {
        let response = ApiError(NivritError::NotFound("user".into())).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn unauthorized_maps_to_401() {
        let response = ApiError(NivritError::Unauthorized).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forbidden_maps_to_403() {
        let response = ApiError(NivritError::Forbidden).into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn validation_maps_to_400() {
        let response = ApiError(NivritError::Validation("bad input".into())).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn conflict_maps_to_409() {
        let response = ApiError(NivritError::Conflict("already exists".into())).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn crypto_and_internal_map_to_500() {
        let crypto = ApiError(NivritError::Crypto("bad key".into())).into_response();
        let internal = ApiError(NivritError::Internal("db down".into())).into_response();
        assert_eq!(crypto.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
