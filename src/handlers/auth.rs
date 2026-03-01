use crate::extractors::validation::ValidJson;
use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    response::Html,
};
use http::HeaderMap;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::auth::*;
use crate::services::auth::{login, password, register, session};
use crate::state::AuthState;

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
    State(auth_state): State<AuthState>,
    ValidJson(payload): ValidJson<RegisterRequest>,
) -> Result<RegisterResponse, AppError> {
    register::register_user(&auth_state, payload).await
}

/// Check user verification status
///
/// Used by the frontend for short polling to determine if the user has clicked the email verification link.
#[utoipa::path(
    get,
    path = "/auth/check-status/{user_id}",
    params(
        ("user_id" = Uuid, Path, description = "The UUID of the user to check")
    ),
    responses(
        (status = 200, body = CheckStatusResponse),
        (status = 400, body = BadRequest),
    ),
    tag = "auth",
)]
pub async fn check_status(
    State(auth_state): State<AuthState>,
    Path(user_id): Path<Uuid>,
) -> Result<CheckStatusResponse, AppError> {
    register::check_status(&auth_state, user_id).await
}

/// Resend verification email
///
/// Generates a new JWT verification token and resends the verification email.
#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    request_body = ResendVerificationRequest,
    responses((status = 200, body = ResendVerificationResponse)),
    tag = "auth",
)]
pub async fn resend_verification(
    State(auth_state): State<AuthState>,
    ValidJson(payload): ValidJson<ResendVerificationRequest>,
) -> Result<ResendVerificationResponse, AppError> {
    register::resend_verification(&auth_state, payload).await
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
    State(auth_state): State<AuthState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ValidJson(payload): ValidJson<LoginRequest>,
) -> Result<LoginResponse, AppError> {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').map(str::trim).find(|s| !s.is_empty()).map(str::to_string))
        .unwrap_or_else(|| addr.ip().to_string());

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    login::authenticate_user(&auth_state, payload, Some(ip_address), user_agent).await
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
    State(auth_state): State<AuthState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<LogoutResponse, AppError> {
    session::invalidate_session(&auth_state, payload).await
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
    State(auth_state): State<AuthState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<RefreshResponse, AppError> {
    session::refresh_session(&auth_state, payload).await
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
    State(auth_state): State<AuthState>,
    ValidJson(payload): ValidJson<ForgotPasswordRequest>,
) -> Result<ForgotPasswordResponse, AppError> {
    password::send_forgot_password_email(&auth_state, payload).await
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
    State(auth_state): State<AuthState>,
    ValidJson(payload): ValidJson<ResetPasswordRequest>,
) -> Result<ResetPasswordResponse, AppError> {
    password::reset_password(&auth_state, payload).await
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
    State(auth_state): State<AuthState>,
    Query(query): Query<TokenQuery>,
) -> Html<String> {
    let outcome = register::verify_email(&auth_state, &query.token).await;

    let (title, message, is_success) = match outcome {
        VerifyEmailOutcome::Success => (
            "Email Verified!",
            "Your account is now active. You can safely close this browser window and return to the StuPass app to log in.",
            true,
        ),
        VerifyEmailOutcome::AlreadyVerified => (
            "Already Verified",
            "Your email is already verified! You can safely close this window and log in to the StuPass app.",
            true,
        ),
        VerifyEmailOutcome::InvalidOrExpiredToken => (
            "Verification Failed",
            "This link is invalid or has expired. Please request a new verification email from the app.",
            false,
        ),
        VerifyEmailOutcome::UserNotFound => (
            "User Not Found",
            "We couldn't find an account associated with this link.",
            false,
        ),
        VerifyEmailOutcome::DatabaseError => (
            "Server Error",
            "Something went wrong on our end. Please try again later.",
            false,
        ),
    };

    render_verification_html(title, message, is_success)
}

/// Renders the email verification result as a mobile-friendly HTML page.
fn render_verification_html(title: &str, message: &str, is_success: bool) -> Html<String> {
    let color = if is_success { "#4CAF50" } else { "#F44336" };
    let icon = if is_success { "✅" } else { "❌" };

    Html(format!(
        r#"<!DOCTYPE html>
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
           </html>"#
    ))
}
