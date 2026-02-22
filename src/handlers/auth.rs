use axum::{Json, extract::Query, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, IntoResponses, ToSchema};
use uuid::Uuid;
use sea_orm::{TransactionTrait, ActiveModelTrait, Set};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use tracing::{info, debug, error};
use tokio::task;
use chrono::Utc;

use crate::state::AppState;
use crate::errors::AppError;
use crate::entities::{credential, user};

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse<T> {
    pub message: T,
}

// ============================================================================
// Request DTOs
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
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
        
        argon2.hash_password(password_to_hash.as_bytes(), &salt)
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

    let inserted_user = new_user
        .insert(&txn)
        .await
        .map_err(|e| {
            error!("Failed to insert user: {:?}", e);
            AppError::InternalServerError
        })?;

    debug!("User record created with ID: {}. Inserting Credential record...", inserted_user.id);

    let new_credential = credential::ActiveModel {
        id: Set(Uuid::new_v4()),
        identifier: Set(payload.phone.clone()), 
        secret: Set(hashed_password),
        provider_id: Set(1), 
        user_id: Set(inserted_user.id),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };

    new_credential
        .insert(&txn)
        .await
        .map_err(|e| {
            error!("Failed to insert credential: {:?}", e);
            AppError::InternalServerError
        })?;

    debug!("Credential record created. Committing transaction...");

    txn
        .commit()
        .await
        .map_err(|e| {
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
pub async fn login(Json(_payload): Json<LoginRequest>) -> Json<LoginResponse> {
    todo!("Implement login with Session creation, return JWT tokens")
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
