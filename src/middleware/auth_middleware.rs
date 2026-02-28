use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use sea_orm::EntityTrait;
use tracing::error;

use crate::{entities::user, errors::AppError, models::auth::Claims, state::AppState};

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| {
            error!("Missing Authorization header");
            AppError::Unauthorized
        })?;

    if !auth_header.starts_with("Bearer ") {
        error!("Authorization header must start with Bearer");
        return Err(AppError::Unauthorized);
    }

    let token = auth_header.trim_start_matches("Bearer ");

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 10;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt.secret.as_bytes()),
        &validation,
    )
    .map_err(|e| {
        error!("JWT verification failed: {:?}", e);
        AppError::Unauthorized
    })?;

    let user_id = uuid::Uuid::parse_str(&token_data.claims.sub).map_err(|e| {
        error!("Failed to parse UUID from token: {}", e);
        AppError::Unauthorized
    })?;

    let user_record = user::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
        .map_err(|e| {
            error!(
                "Database error during auth middleware for user {}: {:?}",
                user_id, e
            );
            AppError::InternalServerError(e.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Token is mathematically valid, but user {} not found in database",
                user_id
            );
            AppError::Unauthorized
        })?;

    if user_record.deleted_at.is_some() {
        error!("Soft-deleted user {} attempted to use a valid JWT", user_id);
        return Err(AppError::Unauthorized);
    }

    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}
