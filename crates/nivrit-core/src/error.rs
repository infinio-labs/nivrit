use thiserror::Error;

#[derive(Debug, Error)]
pub enum NivritError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("validation error: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, NivritError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(
            NivritError::NotFound("user".into()).to_string(),
            "not found: user"
        );
        assert_eq!(NivritError::Unauthorized.to_string(), "unauthorized");
        assert_eq!(NivritError::Forbidden.to_string(), "forbidden");
        assert_eq!(
            NivritError::Validation("email required".into()).to_string(),
            "validation error: email required"
        );
        assert_eq!(
            NivritError::Conflict("already exists".into()).to_string(),
            "conflict: already exists"
        );
        assert_eq!(
            NivritError::Crypto("bad key".into()).to_string(),
            "crypto error: bad key"
        );
        assert_eq!(
            NivritError::Internal("db down".into()).to_string(),
            "internal error: db down"
        );
    }
}
