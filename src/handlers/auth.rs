use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{Json, extract::Query, extract::State, response::Html};
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
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::entities::{
    auth_provider, credential, password_reset_token, session, user
};
use crate::entities::prelude::{
    AuthProvider, Credential, PasswordResetToken, Session, User
};
use crate::errors::AppError;
use crate::state::AppState;
use crate::util::send_password_reset_email::send_password_reset_email;
use crate::util::send_verification_email::send_verification_email;

// ============================================================================
// JWT Claims
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub exp: usize,  // expiration (Unix timestamp)
    pub iat: usize,  // issued at (Unix timestamp)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailVerifyClaims {
    pub sub: Uuid,
    pub exp: usize,
    pub purpose: String,
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
    pub email: String,
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
    pub email: String,
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
    info!("Starting registration process for email: {}", payload.email);

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
        email: Set(payload.email.clone()), 
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
        identifier: Set(payload.email.clone()),
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
    
    // ==========================================
    // Generate Verification Token & Send Email
    // ==========================================
    
    // 1. Create a 24-hour expiration token
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = EmailVerifyClaims {
        sub: inserted_user.id,
        exp: expiration,
        purpose: String::from("email_verification"),
    };

    let verify_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt.secret.as_bytes()),
    ).map_err(|e| {
        error!("Failed to sign verification token: {:?}", e);
        AppError::InternalServerError
    })?;

    // 2. Build your deep link
    let deep_link = format!("{}/auth/verify-email?token={}", state.server_url, verify_token);

    // 3. Fire the email using our new Resend helper
    let email_result = send_verification_email(
        &state.http_client,
        &state.resend_api_key,
        &payload.email,
        &deep_link,
    ).await;

    // 4. Handle email delivery failures gracefully
    if let Err(e) = email_result {
        error!("User {} registered, but Resend failed to send email: {:?}", inserted_user.id, e);
        // We still return Ok() because the user IS in the database.
        // The frontend can prompt them to "Resend Verification Email" later.
        return Ok(Json(RegisterResponse {
            user_id: inserted_user.id,
            message: String::from("User registered, but we had trouble sending the verification email. Please try requesting a new one later."),
        }));
    }

    Ok(Json(RegisterResponse {
        user_id: inserted_user.id,
        message: String::from("User registered successfully! Please check your email to verify your account."),
    }))}

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
            AppError::Unauthorized
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
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {

    let token_str = payload.refresh_token.as_deref().ok_or(AppError::Unauthorized)?;
    let incoming_hash = hash_token(token_str);

    // Find and delete the session.
    let result = Session::delete_many()
        .filter(session::Column::SessionTokenHash.eq(incoming_hash))
        .exec(&state.db)
        .await
        .map_err(|e| {
            error!("Database error during logout: {:?}", e);
            AppError::InternalServerError
        })?;

    if result.rows_affected == 0 {
        debug!("Logout requested for token that doesn't exist. Treating as success.");
    }

    Ok(Json(LogoutResponse(
        MessageResponse{ message: String::from("Successfully logged out") }
    )))
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
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {

    let incoming_hash = hash_token(&payload.refresh_token);

    // Look up the session in the database
    let session_record: session::Model = Session::find()
        .filter(session::Column::SessionTokenHash.eq(&incoming_hash))
        .one(&state.db)
        .await
        .map_err(|e| {
            error!("Database error during session lookup: {:?}", e);
            AppError::InternalServerError
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
        let _ = session_record.clone().delete(&state.db).await;
        
        return Err(AppError::Unauthorized);
    }

    // Generate the new Access Token (JWT)
    let new_access_token = generate_access_token(
        session_record.user_id, 
        &state.jwt.secret, 
        state.jwt.access_token_expiry
    )?;

    // Generate a new Refresh Token (Token Rotation)
    let new_refresh_token = generate_session_token();
    let new_refresh_hash = hash_token(&new_refresh_token);
    let new_expires_at = now + Duration::seconds(state.jwt.refresh_token_expiry);

    // Update the existing session record with the new hash and expiration
    let mut active_session: session::ActiveModel = session_record.into();
    active_session.session_token_hash = Set(new_refresh_hash);
    active_session.last_refresh = Set(now);
    active_session.expires_at = Set(new_expires_at);

    active_session.update(&state.db).await.map_err(|e| {
        error!("Failed to update session: {:?}", e);
        AppError::InternalServerError
    })?;

    // Return the new pair to the user
    Ok(Json(RefreshResponse {
        tokens: AuthTokens {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            expires_in: state.jwt.access_token_expiry,
        },
    }))
}

/// Request password reset
///
/// Sends a password reset email with embedded token link if the email exists.
/// Always returns success to prevent email enumeration attacks.
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
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Json<ForgotPasswordResponse> {
    info!("Password reset requested for email: {}", payload.email);

    // --- Rate limiting check (3 requests per hour per email) ---
    if let Err(remaining_secs) = state.rate_limiter.check_password_reset(&payload.email) {
        info!(
            "Password reset rate limited for email: {}. Try again in {} seconds",
            payload.email, remaining_secs
        );
        // Still return success to prevent email enumeration
        return Json(ForgotPasswordResponse(MessageResponse {
            message: format!(
                "If an account with that email exists, we've sent a password reset link.\
                 \n\nNote: Too many requests. Please try again in {} minutes.",
                remaining_secs / 60 + 1
            ),
        }));
    }

    let success_response = || Json(ForgotPasswordResponse(MessageResponse {
        message: String::from("If an account with that email exists, we've sent a password reset link."),
    }));

    // --- 1. Find user by email ---
    let user_record = User::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&state.db)
        .await;

    // Handle lookup result - we proceed silently on errors to prevent enumeration
    let user = match user_record {
        Ok(Some(u)) => u,
        Ok(None) => {
            info!("No user found with email: {} - returning success anyway", payload.email);
            return success_response();
        }
        Err(e) => {
            error!("Database error during password reset lookup: {:?}", e);
            return success_response();
        }
    };

    // --- 2. Generate reset token (64-char random string) ---
    let reset_token = generate_session_token();
    let reset_token_hash = hash_token(&reset_token);

    // --- 3. Calculate expiry (1 hour from now) ---
    let now = Utc::now();
    let expires_at = now + Duration::hours(1);

    // --- 4. Store token hash in database ---
    let new_reset_token = password_reset_token::ActiveModel {
        reset_token_hash: Set(reset_token_hash),
        created_at: Set(now),
        expires_at: Set(expires_at),
        used_at: Set(None),
        user_id: Set(user.id),
        ..Default::default()
    };

    if let Err(e) = new_reset_token.insert(&state.db).await {
        error!("Failed to store password reset token: {:?}", e);
        return success_response();
    }

    // --- 5. Build reset link (frontend URL with token) ---
    let reset_link = format!("{}/reset-password?token={}", state.fe_url, reset_token);

    // --- 6. Send password reset email ---
    let email_result = send_password_reset_email(
        &state.http_client,
        &state.resend_api_key,
        &payload.email,
        &reset_link,
    ).await;

    if let Err(e) = email_result {
        error!("Failed to send password reset email to {}: {:?}", payload.email, e);
        // Still return success to prevent enumeration
    }

    success_response()
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
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AppError> {
    info!("Processing password reset request");

    // --- 1. Hash the incoming token ---
    let token_hash = hash_token(&payload.token);

    // --- 2. Begin transaction early for atomic token validation ---
    let txn = state.db.begin().await.map_err(|e| {
        error!("Failed to begin transaction: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 3. Find and lock the reset token record within transaction ---
    // Using find() inside transaction; for row-level locking you'd use SELECT FOR UPDATE
    // but SeaORM's SQLite backend has limited support. The transaction itself provides
    // isolation for our check-then-act pattern.
    let reset_record = PasswordResetToken::find()
        .filter(password_reset_token::Column::ResetTokenHash.eq(&token_hash))
        .one(&txn)
        .await
        .map_err(|e| {
            error!("Database error during reset token lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            info!("Invalid password reset token");
            AppError::BadRequest(String::from("Invalid or expired reset token"))
        })?;

    // --- 4. Validate token: check expiry ---
    let now = Utc::now();
    if reset_record.expires_at < now {
        info!("Password reset token has expired");
        return Err(AppError::BadRequest(String::from("Reset token has expired")));
    }

    // --- 5. Validate token: check if already used ---
    // Now safe from race condition since we're in a transaction
    if reset_record.used_at.is_some() {
        info!("Password reset token already used");
        return Err(AppError::BadRequest(String::from("Reset token has already been used")));
    }

    let user_id = reset_record.user_id;

    // --- 6. Hash the new password ---
    let new_password = payload.new_password;
    let hashed_password = task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(new_password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|e| {
        error!("Thread pool error during password hashing: {:?}", e);
        AppError::InternalServerError
    })?
    .map_err(|e| {
        error!("Failed to hash new password: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 7. Find the "Password" provider ---
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

    // --- 8. Find and update the credential ---
    let credential_record = Credential::find()
        .filter(credential::Column::UserId.eq(user_id))
        .filter(credential::Column::ProviderId.eq(provider_id))
        .one(&txn)
        .await
        .map_err(|e| {
            error!("Database error during credential lookup: {:?}", e);
            AppError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("No password credential found for user {}", user_id);
            AppError::InternalServerError
        })?;

    let mut cred_active: credential::ActiveModel = credential_record.into();
    cred_active.secret = Set(hashed_password);
    cred_active.updated_at = Set(now);

    cred_active.update(&txn).await.map_err(|e| {
        error!("Failed to update credential: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 9. Mark reset token as used ---
    let mut token_active: password_reset_token::ActiveModel = reset_record.into();
    token_active.used_at = Set(Some(now));

    token_active.update(&txn).await.map_err(|e| {
        error!("Failed to mark reset token as used: {:?}", e);
        AppError::InternalServerError
    })?;

    // --- 10. Invalidate all sessions for this user (security measure) ---
    let delete_result = Session::delete_many()
        .filter(session::Column::UserId.eq(user_id))
        .exec(&txn)
        .await
        .map_err(|e| {
            error!("Failed to invalidate sessions: {:?}", e);
            AppError::InternalServerError
        })?;

    info!("Invalidated {} sessions for user {}", delete_result.rows_affected, user_id);

    // --- 11. Commit transaction ---
    txn.commit().await.map_err(|e| {
        error!("Failed to commit transaction: {:?}", e);
        AppError::InternalServerError
    })?;

    info!("Successfully reset password for user {}", user_id);

    Ok(Json(ResetPasswordResponse(MessageResponse {
        message: String::from("Password has been reset successfully. Please log in with your new password."),
    })))
}

/// Verify email address
///
/// Verifies user email using token from email link (query param).
#[utoipa::path(
    get,
    path = "/auth/verify-email",
    params(TokenQuery),
    responses(
        (status = 200, description = "HTML page showing success or failure"),
    ),
    tag = "auth"
)]
pub async fn verify_email(
    State(state): State<AppState>, 
    Query(query): Query<TokenQuery>,
) -> Html<String> {
    
    // --- 1. HTML Template Helper ---
    // This closure wraps our responses in a clean, mobile-friendly UI
    let render_html = |title: &str, message: &str, is_success: bool| -> Html<String> {
        let color = if is_success { "#4CAF50" } else { "#F44336" };
        let icon = if is_success { "✅" } else { "❌" };
        
        Html(format!(
            r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f9fafb; }}
                    .card {{ background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }}
                    h1 {{ color: {color}; font-size: 24px; margin-bottom: 10px; }}
                    p {{ color: #4b5563; font-size: 16px; line-height: 1.5; }}
                    .icon {{ font-size: 48px; margin-bottom: 16px; }}
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="icon">{icon}</div>
                    <h1>{title}</h1>
                    <p>{message}</p>
                </div>
            </body>
            </html>
            "#
        ))
    };

    info!("Attempting to verify email with provided token");

    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 60; 

    // --- 2. Decode and verify the JWT ---
    let token_data = match decode::<EmailVerifyClaims>(
        &query.token,
        &DecodingKey::from_secret(state.jwt.secret.as_bytes()), 
        &validation,
    ) {
        Ok(data) => data,
        Err(e) => {
            error!("Invalid or expired email verification token: {:?}", e);
            return render_html("Verification Failed", "This link is invalid or has expired. Please request a new verification email from the app.", false);
        }
    };

    // --- 3. Ensure the token is strictly for email verification ---
    if token_data.claims.purpose != "email_verification" {
        error!("Attempted to use invalid token purpose for email verification");
        return render_html("Invalid Link", "This token cannot be used for email verification.", false);
    }

    let user_id = token_data.claims.sub;

    // --- 4. Find the user in the database ---
    let user_record = match user::Entity::find_by_id(user_id).one(&state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            error!("User {} not found during verification", user_id);
            return render_html("User Not Found", "We couldn't find an account associated with this link.", false);
        }
        Err(e) => {
            error!("Database error finding user during verification: {:?}", e);
            return render_html("Server Error", "Something went wrong on our end. Please try again later.", false);
        }
    };

    // --- 5. Idempotency Check: Return success if already verified ---
    if user_record.verified_at.is_some() {
        info!("User {} is already verified", user_id);
        return render_html("Already Verified", "Your email is already verified! You can safely close this window and log in to the StuPass app.", true);
    }

    // --- 6. Update the User's verification status ---
    let mut active_user: user::ActiveModel = user_record.into();
    active_user.verification_status = Set(String::from("verified"));
    active_user.verified_at = Set(Some(Utc::now()));
    active_user.updated_at = Set(Utc::now());

    if let Err(e) = active_user.update(&state.db).await {
        error!("Failed to update user verification status: {:?}", e);
        return render_html("Server Error", "Failed to save your verification status. Please try again.", false);
    }

    info!("Successfully verified email for user {}", user_id);

    // --- 7. Final Success Page ---
    render_html("Email Verified!", "Your account is now active. You can safely close this browser window and return to the StuPass app to log in.", true)
}