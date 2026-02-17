use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug)]
pub enum AppError {
    AuthError(String),
    BadRequest(String),
    DatabaseError(String),
    PdsError(String),
    InternalError(String),
    NotFound(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::AuthError(msg) => write!(f, "Auth Error: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            AppError::DatabaseError(msg) => write!(f, "Database Error: {}", msg),
            AppError::PdsError(msg) => write!(f, "PDS Error: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal Error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not Found: {}", msg),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status_code = match self {
            AppError::AuthError(_) => StatusCode::UNAUTHORIZED,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PdsError(_) => StatusCode::BAD_GATEWAY,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
        };

        let body = Json(ErrorResponse {
            status: "error".to_string(),
            message: self.to_string(),
        });

        (status_code, body).into_response()
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(error: diesel::result::Error) -> Self {
        AppError::DatabaseError(error.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(error: reqwest::Error) -> Self {
        AppError::PdsError(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", AppError::AuthError("test".to_string())),
            "Auth Error: test"
        );
        assert_eq!(
            format!("{}", AppError::DatabaseError("test".to_string())),
            "Database Error: test"
        );
        assert_eq!(
            format!("{}", AppError::PdsError("test".to_string())),
            "PDS Error: test"
        );
        assert_eq!(
            format!("{}", AppError::InternalError("test".to_string())),
            "Internal Error: test"
        );
        assert_eq!(
            format!("{}", AppError::NotFound("test".to_string())),
            "Not Found: test"
        );
    }

    #[test]
    fn test_error_response() {
        let err = AppError::AuthError("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
