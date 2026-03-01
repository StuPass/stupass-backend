use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, IntoResponses, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageResponse<T> {
    pub message: T,
}

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
// Request DTOs
// ============================================================================

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, message = "Username must be at least 3 characters long"))]
    pub username: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
    pub password: String,
    #[validate(length(min = 1, message = "Full name cannot be empty"))]
    pub full_name: String,
    #[validate(length(min = 1, message = "Student ID cannot be empty"))]
    pub student_id: String,
    #[validate(length(min = 1, message = "School ID cannot be empty"))]
    pub school_id: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ResendVerificationRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
    #[validate(length(min = 1, message = "Identifier cannot be empty"))]
    pub identifier: String,
    #[validate(length(min = 1, message = "Password cannot be empty"))]
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

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ForgotPasswordRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, ToSchema, Validate)]
pub struct ResetPasswordRequest {
    /// Reset token from email link (extracted by frontend from URL)
    #[validate(length(min = 1, message = "Token cannot be empty"))]
    pub token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters long"))]
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 201)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub message: String,
}

impl IntoResponse for RegisterResponse {
    fn into_response(self) -> Response {
        (StatusCode::CREATED, Json(self)).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct CheckStatusResponse {
    pub verification_status: String,
    pub profile_completed: bool,
}

impl IntoResponse for CheckStatusResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct LoginResponse {
    #[serde(flatten)]
    pub tokens: AuthTokens,
}

impl IntoResponse for LoginResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 200)]
pub struct RefreshResponse {
    #[serde(flatten)]
    pub tokens: AuthTokens,
}

impl IntoResponse for RefreshResponse {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

// A generic wrapper macro to easily create 200 OK responses with just a message
macro_rules! impl_message_response {
    ($name:ident) => {
        #[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
        #[response(status = 200)]
        pub struct $name(pub MessageResponse<String>);

        impl IntoResponse for $name {
            fn into_response(self) -> Response {
                Json(self.0).into_response()
            }
        }
    };
}

// This macro drastically reduces boilerplate for all your simple success responses!
impl_message_response!(LogoutResponse);
impl_message_response!(ForgotPasswordResponse);
impl_message_response!(ResetPasswordResponse);
impl_message_response!(VerifyEmailResponse);
impl_message_response!(CompleteProfileResponse);
impl_message_response!(ResendVerificationResponse);

// ============================================================================
// Error Responses
// ============================================================================

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 400)]
pub struct BadRequest(pub MessageResponse<String>);

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 401)]
pub struct Unauthorized(pub MessageResponse<String>);

#[derive(Debug, Serialize, Deserialize, ToSchema, IntoResponses)]
#[response(status = 409)]
pub struct Conflict(pub MessageResponse<String>);

// Enums
pub enum VerifyEmailOutcome {
    Success,
    AlreadyVerified,
    InvalidOrExpiredToken,
    UserNotFound,
    DatabaseError,
}
