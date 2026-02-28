use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InternalServerError(String),
    Unauthorized,
    NotFound,
    BadRequest(String),
    Conflict(String),
}

pub fn internal_error<E: std::fmt::Display>(err: E) -> AppError {
    tracing::error!("Internal error: {}", err);
    AppError::InternalServerError(err.to_string())
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::InternalServerError(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal Server Error: {}", message),
            ),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, String::from("Unauthorized")),
            Self::NotFound => (StatusCode::NOT_FOUND, String::from("Not found")),
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                format!("Bad request error: {message}"),
            ),
            Self::Conflict(message) => (StatusCode::CONFLICT, format!("Conflict: {message}")),
        };
        (status, Json(json!({ "message": err_msg }))).into_response()
    }
}
