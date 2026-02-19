use axum::{
    Router,
    routing::{get, post},
    http::StatusCode,
    response::IntoResponse
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers::auth;
use crate::handlers::general;
use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        general::health,
        auth::register,
        auth::login,
        auth::logout,
        auth::refresh,
        auth::forgot_password,
        auth::reset_password,
        auth::verify_email,
    ),
    components(schemas(
        auth::RegisterRequest,
        auth::LoginRequest,
        auth::LogoutRequest,
        auth::RefreshRequest,
        auth::ForgotPasswordRequest,
        auth::ResetPasswordRequest,
        auth::TokenQuery,
        auth::AuthTokens,
        auth::RegisterResponse,
        auth::LoginResponse,
        auth::LogoutResponse,
        auth::RefreshResponse,
        auth::ForgotPasswordResponse,
        auth::ResetPasswordResponse,
        auth::VerifyEmailResponse,
        auth::BadRequest,
        auth::Unauthorized,
        auth::Conflict,
    )),
    tags(
        (name = "general", description = "General endpoints"),
        (name = "auth", description = "Authentication endpoints"),
    ),
)]
struct ApiDoc;

// Function to create the main application router
pub fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(general::health))
        // Auth routes
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/verify-email", get(auth::verify_email))
        .fallback(handler_404)
        .with_state(state)
        // Swagger UI at root
        .merge(SwaggerUi::new("/").url("/api-docs/openapi.json", ApiDoc::openapi()))
}

// Handler for 404 Not Found errors
async fn handler_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        "The requested resource was not found",
    )
}
