use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    InternalServerError,
    Unauthorized,
    NotFound,
    BadRequest(String),
    Conflict(String),
}

pub fn internal_error<E: std::fmt::Display>(err: E) -> AppError {
    tracing::error!("Internal error: {}", err);
    AppError::InternalServerError
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, err_msg) = match self {
            Self::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Internal Server Error"),
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                String::from("Unauthorized"),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                String::from("Not found"),
            ),
            Self::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                format!("Bad request error: {message}"),
            ),
            Self::Conflict(message) => (
                StatusCode::CONFLICT,
                format!("Conflict: {message}"),
            ),
        };
        (status, Json(json!({ "message": err_msg }))).into_response()
    }
}