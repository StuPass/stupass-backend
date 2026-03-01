use chrono::{Duration, Utc};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tracing::{debug, error, info};

use crate::{
    entities::prelude::Session, entities::session, errors::AppError, models::auth::*,
    services::auth::AuthDeps, utils::jwt_token::*,
};

pub async fn refresh_session<D: AuthDeps>(
    deps: &D,
    req: RefreshRequest,
) -> Result<RefreshResponse, AppError> {
    let RefreshRequest { refresh_token } = req;

    let incoming_hash = hash_token(&refresh_token);

    // Look up the session in the database
    let session_record: session::Model = Session::find()
        .filter(session::Column::SessionTokenHash.eq(&incoming_hash))
        .one(deps.db())
        .await
        .map_err(|e| {
            error!("Database error during session lookup: {:?}", e);
            AppError::InternalServerError(e.to_string())
        })?
        .ok_or_else(|| {
            info!("Attempted to refresh with invalid or expired token.");
            AppError::Unauthorized // Return 401 to force the user to log in again
        })?;

    let now = Utc::now();

    // Check if the session has expired
    if session_record.expires_at < now {
        info!("Refresh token expired for user: {}", session_record.user_id);

        // Delete the expired session
        let _ = session_record.clone().delete(deps.db()).await;

        return Err(AppError::Unauthorized);
    }

    // Generate the new Access Token (JWT)
    let new_access_token = generate_access_token(
        session_record.user_id,
        &deps.jwt().secret,
        deps.jwt().access_token_expiry,
    )?;

    // Generate a new Refresh Token (Token Rotation)
    let new_refresh_token = generate_session_token();
    let new_refresh_hash = hash_token(&new_refresh_token);
    let new_expires_at = now + Duration::seconds(deps.jwt().refresh_token_expiry);

    // Update the existing session record with the new hash and expiration
    let mut active_session: session::ActiveModel = session_record.into();
    active_session.session_token_hash = Set(new_refresh_hash);
    active_session.last_refresh = Set(now);
    active_session.expires_at = Set(new_expires_at);

    active_session.update(deps.db()).await.map_err(|e| {
        error!("Failed to update session: {:?}", e);
        AppError::InternalServerError(e.to_string())
    })?;

    // Return the new pair to the user
    Ok(RefreshResponse {
        tokens: AuthTokens {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            expires_in: deps.jwt().access_token_expiry,
        },
    })
}

pub async fn invalidate_session<D: AuthDeps>(
    deps: &D,
    req: LogoutRequest,
) -> Result<LogoutResponse, AppError> {
    let LogoutRequest { refresh_token } = req;

    let token_str = refresh_token.as_deref().ok_or(AppError::Unauthorized)?;
    let incoming_hash = hash_token(token_str);

    // Find and delete the session.
    let result = Session::delete_many()
        .filter(session::Column::SessionTokenHash.eq(incoming_hash))
        .exec(deps.db())
        .await
        .map_err(|e| {
            error!("Database error during logout: {:?}", e);
            AppError::InternalServerError(e.to_string())
        })?;

    if result.rows_affected == 0 {
        debug!("Logout requested for token that doesn't exist. Treating as success.");
    }

    Ok(LogoutResponse(MessageResponse {
        message: String::from("Successfully logged out"),
    }))
}
