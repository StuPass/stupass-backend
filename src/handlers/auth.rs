use axum::{Json, extract::Query};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, IntoResponses, ToSchema};
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse<T> {
    pub message: T,
}

// ============================================================================
// Request DTOs
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub full_name: String,
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
pub async fn register(Json(_payload): Json<RegisterRequest>) -> Json<RegisterResponse> {
    todo!("Implement registration with User + Credential creation, send verification email")
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
