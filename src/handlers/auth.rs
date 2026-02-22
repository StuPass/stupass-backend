use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{Json, extract::Query, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::RngCore;
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, EntityTrait, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::task;
use tracing::{debug, error, info};
use utoipa::{IntoParams, IntoResponses, ToSchema};
use uuid::Uuid;

use crate::entities::{
    auth_provider, auth_provider::Entity as AuthProvider, credential,
    credential::Entity as Credential, session, user,
};
use crate::errors::AppError;
use crate::state::AppState;

// ============================================================================
// JWT Claims
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,  // expiration (Unix timestamp)
    pub iat: usize,  // issued at (Unix timestamp)
}

// ============================================================================
// Token Generation Helpers
// ============================================================================

/// Generate a 64-character random session token (base64-encoded)
fn generate_session_token() -> String {
    let mut bytes = [0u8; 48]; // 48 bytes -> 64 base64 chars
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token using SHA256
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Generate a JWT access token
fn generate_access_token(
    user_id: Uuid,
    secret: &str,
    expiry_seconds: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let exp = now + Duration::seconds(expiry_seconds);

    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| {
        error!("Failed to encode JWT: {:?}", e);
        AppError::InternalServerError
    })
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse<T> {
    pub message: T,
}

// ============================================================================
// Request DTOs
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub phone: String,
    pub password: String,
    pub full_name: String,
    pub student_id: String,
    pub school_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LogoutRequest {
    /// Refresh token to invalidate (access token from Authorization header)
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ForgotPasswordRequest {
    pub phone: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    /// Reset token from email link (extracted by frontend from URL)
    pub token: String,
    pub new_password: String,
}

/// Token extracted from email link query parameter
#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct TokenQuery {
    pub token: String,
}

// ============================================================================
// Response DTOs
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 201)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct LoginResponse {
    #[serde(flatten)]
    pub tokens: AuthTokens,
}

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct LogoutResponse(pub MessageResponse<String>);

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct RefreshResponse {
    #[serde(flatten)]
    pub tokens: AuthTokens,
}

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct ForgotPasswordResponse(pub MessageResponse<String>);

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct ResetPasswordResponse(pub MessageResponse<String>);

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct VerifyEmailResponse(pub MessageResponse<String>);

// ============================================================================
// Error Responses
// ============================================================================

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 400)]
pub struct BadRequest(pub MessageResponse<String>);

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 401)]
pub struct Unauthorized(pub MessageResponse<String>);

#[derive(Debug, Serialize, ToSchema, IntoResponses)]
#[response(status = 409)]
pub struct Conflict(pub MessageResponse<String>);

// ============================================================================
// Handlers
// ============================================================================

/// Register a new user
///
/// Creates a new user account with email/password credentials and sends verification email.
#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, body = RegisterResponse),
        (status = 400, body = BadRequest),
        (status = 409, body = Conflict),
    ),
    tag = "auth",
)]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    info!("Starting registration process for phone: {}", payload.phone);

    let password_to_hash = payload.password.clone();

    debug!("Offloading password hashing to background thread...");

    let hashed_password = task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(password_to_hash.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password hashing: {:?}", e);
        AppError::InternalServerError
    })?
    .map_err(|e| {
        error!("Failed to hash password: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Password hashed successfully. Initiating database transaction.");

    let txn = state.db.begin().await.map_err(|e| {
        error!("Failed to begin txn: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Inserting User record...");

    let now = Utc::now();

    let new_user = user::ActiveModel {
        id: Set(Uuid::new_v4()),
        username: Set(payload.username.clone()),
        email: Set(format!("{}@placeholder.edu", payload.username)), // TODO: FE add email-password based registration
        phone: Set(payload.phone.clone()),
        full_name: Set(payload.full_name),
        school_id: Set(payload.school_id),
        student_id: Set(payload.student_id),
        reputation_score: Set(10),
        verification_status: Set(String::from("pending")),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    let inserted_user = new_user.insert(&txn).await.map_err(|e| {
        error!("Failed to insert user: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!(
        "User record created with ID: {}. Inserting Credential record...",
        inserted_user.id
    );

    let provider_id = AuthProvider::find()
        .filter(auth_provider::Column::Name.eq("Password"))
        .one(&txn)
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

    let new_credential = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(payload.phone.clone()),
        secret: Set(hashed_password),
        provider_id: Set(provider_id),
        user_id: Set(inserted_user.id),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    new_credential.insert(&txn).await.map_err(|e| {
        error!("Failed to insert credential: {:?}", e);
        AppError::InternalServerError
    })?;

    debug!("Credential record created. Committing transaction...");

    txn.commit().await.map_err(|e| {
        error!("Failed to commit txn: {:?}", e);
        AppError::InternalServerError
    })?;

    info!("Successfully registered user ID: {}", inserted_user.id);

    Ok(Json(RegisterResponse {
        user_id: inserted_user.id,
        message: String::from("User registered successfully!"),
    }))
}

/// Login with credentials
///
/// Authenticates user with email/username and password, returns JWT tokens.
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, body = LoginResponse),
        (status = 401, body = Unauthorized),
    ),
    tag = "auth",
)]
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // TODO: Add ConnectInfo argument
    info!("Login attempt for identifier: {}", payload.identifier);

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
        .filter(credential::Column::Identifier.eq(&payload.identifier))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error during credential lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            info!("No credential found for identifier: {}", payload.identifier);
            AppError::InternalServerError
        })?;

    // Retain user_id before moving credential into spawn_blocking
    let user_id = credential.user_id;

    // Verify payload password against stored hash
    let verify_result = task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&credential.secret).unwrap();

        Argon2::default()
            .verify_password(payload.password.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password verification: {:?}", e);
        AppError::InternalServerError
    })?;

    if !verify_result {
        info!("Invalid password for identifier: {}", payload.identifier);
        return Err(AppError::InternalServerError);
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

    Ok(Json(LoginResponse {
        tokens: AuthTokens {
            access_token,
            refresh_token,
            expires_in: state.jwt.access_token_expiry,
        },
    }))
}

/// Logout and invalidate session
///
/// Invalidates the current session. Uses refresh token from body or access token from Authorization header.
#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body = LogoutRequest,
    responses(
        (status = 200, body = LogoutResponse),
        (status = 401, body = Unauthorized),
    ),
    tag = "auth",
)]
pub async fn logout(Json(_payload): Json<LogoutRequest>) -> Json<LogoutResponse> {
    todo!("Implement session invalidation")
}

/// Refresh access token
///
/// Exchange a valid refresh token for new access and refresh tokens.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, body = RefreshResponse),
        (status = 401, body = Unauthorized),
    ),
    tag = "auth",
)]
pub async fn refresh(Json(_payload): Json<RefreshRequest>) -> Json<RefreshResponse> {
    todo!("Implement session token refresh, rotate refresh token")
}

/// Request password reset
///
/// Sends a password reset email with embedded token link if the email exists.
#[utoipa::path(
    post,
    path = "/auth/forgot-password",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, body = ForgotPasswordResponse),
    ),
    tag = "auth",
)]
pub async fn forgot_password(
    Json(_payload): Json<ForgotPasswordRequest>,
) -> Json<ForgotPasswordResponse> {
    todo!("Implement PasswordResetToken creation and email sending")
}

/// Reset password with token
///
/// Completes password reset. Token extracted from email link by frontend, sent in body.
#[utoipa::path(
    post,
    path = "/auth/reset-password",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, body = ResetPasswordResponse),
        (status = 400, body = BadRequest),
        (status = 401, body = Unauthorized),
    ),
    tag = "auth",
)]
pub async fn reset_password(
    Json(_payload): Json<ResetPasswordRequest>,
) -> Json<ResetPasswordResponse> {
    todo!("Implement password validation and PasswordResetToken.mark_as_used")
}

/// Verify email address
///
/// Verifies user email using token from email link (query param).
#[utoipa::path(
    get,
    path = "/auth/verify-email",
    params(TokenQuery),
    responses(
        (status = 200, body = VerifyEmailResponse),
        (status = 400, body = BadRequest),
    ),
    tag = "auth"
)]
pub async fn verify_email(Query(_query): Query<TokenQuery>) -> Json<VerifyEmailResponse> {
    todo!("Implement email verification and User.verified_at update")
}
