use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc};
use sea_orm::prelude::*;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use tokio::task;
use tracing::{error, info};

use crate::{
    entities::prelude::{AuthProvider, Credential},
    entities::{auth_provider, credential, session},
    errors::AppError,
    models::auth::{AuthTokens, LoginRequest, LoginResponse},
    state::AppState,
    utils::jwt_token::*,
};

pub async fn authenticate_user(
    state: &AppState,
    req: LoginRequest,
) -> Result<LoginResponse, AppError> {
    // TODO: Add ConnectInfo argument

    let LoginRequest {
        identifier,
        password,
    } = req;

    info!("Login attempt for identifier: {}", identifier);

    // Lookup "Password" provider ID (assumes it exists)
    let provider_id = AuthProvider::find()
        .filter(auth_provider::Column::Name.eq("Password"))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error during auth provider lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("Auth provider 'Password' not found in database");
            AppError::InternalServerError
        })?
        .id;

    // Lookup Credential with "Password" provider and identifier
    let credential: credential::Model = Credential::find()
        .filter(credential::Column::ProviderId.eq(provider_id))
        .filter(credential::Column::Identifier.eq(&identifier))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error during credential lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            info!("No credential found for identifier: {}", &identifier);
            AppError::Unauthorized
        })?;

    // Retain user_id before moving credential into spawn_blocking
    let user_id: Uuid = credential.user_id;

    // Verify payload password against stored hash
    let verify_result: bool = task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&credential.secret).unwrap();

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password verification: {:?}", e);
        AppError::InternalServerError
    })?;

    if !verify_result {
        info!("Invalid password for identifier: {}", identifier);
        return Err(AppError::Unauthorized);
    }

    // Generate access token (JWT)
    let access_token =
        generate_access_token(user_id, &state.jwt.secret, state.jwt.access_token_expiry)?;

    // Generate refresh token (64-char random string)
    let refresh_token = generate_session_token();
    let refresh_token_hash = hash_token(&refresh_token);

    // Create session record
    let now = Utc::now();
    let expires_at = now + Duration::seconds(state.jwt.refresh_token_expiry);

    let new_session = session::ActiveModel {
        session_token_hash: Set(refresh_token_hash),
        ip_address: Set(None), // TODO: Extract IP from request or headers
        user_agent: Set(None), // TODO: Extract User-Agent from request headers
        valid_from: Set(now),
        expires_at: Set(expires_at),
        last_refresh: Set(now),
        user_id: Set(user_id),
        ..Default::default()
    };

    new_session.insert(&state.db).await.map_err(|e| {
        error!("Failed to create session: {:?}", e);
        AppError::InternalServerError
    })?;

    Ok(LoginResponse {
        tokens: AuthTokens {
            access_token,
            refresh_token,
            expires_in: state.jwt.access_token_expiry,
        },
    })
}
