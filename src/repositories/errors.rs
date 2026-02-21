use std::fmt;
use sea_orm::error::DbErr;
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(Debug)]
pub enum DbError {
    InternalServerError,
    NotFound,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "Data not found"),
            Self::InternalServerError => write!(f, "Internal server error"),
        }
    }
}

impl From<DbErr> for DbError {
    fn from(error: DbErr) -> Self {
        match error {
            DbErr::RecordNotFound(_) => Self::NotFound,
            other => {
                tracing::error!("Database Error: {:?}", other);
                Self::InternalServerError
            }
        }
    }
}

impl IntoResponse for DbError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            Self::InternalServerError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error"),
            Self::NotFound => (StatusCode::NOT_FOUND, "Resource not found"),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}