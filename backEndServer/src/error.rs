use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    #[error("User Already Exists")]
    UserExists,
    #[error("Invalid Credential")]
    InvalidCredential,
    #[error("Database Error")]
    DatabaseError,
    #[error("Deserialising Session failed: {0}")]
    InvalidSessionState(#[from] tower_sessions::session::Error),
    #[error("User not authenticated")]
    Unauthenticated,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let (status, body): (StatusCode, String) = match self {
            WebauthnError::CorruptSession => (StatusCode::BAD_REQUEST, "Corrupt Session".to_string()),
            WebauthnError::UserNotFound => (StatusCode::NOT_FOUND, "User Not Found".to_string()),
            WebauthnError::Unknown => (StatusCode::INTERNAL_SERVER_ERROR, "Unknown Error".to_string()),
            WebauthnError::UserHasNoCredentials => (StatusCode::BAD_REQUEST, "User Has No Credentials".to_string()),
            WebauthnError::InvalidSessionState(_) => (StatusCode::BAD_REQUEST, "Deserialising Session failed".to_string()),
            WebauthnError::UserExists => (StatusCode::CONFLICT, "User Already Exists".to_string()),
            WebauthnError::InvalidCredential => (StatusCode::BAD_REQUEST, "Invalid Credential".to_string()),
            WebauthnError::DatabaseError => (StatusCode::INTERNAL_SERVER_ERROR, "Database Error".to_string()),
            WebauthnError::Unauthenticated => (StatusCode::UNAUTHORIZED, "User not authenticated".to_string()),
            WebauthnError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        (status, body).into_response()
    }
}