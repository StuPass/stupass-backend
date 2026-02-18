use axum::{
    Router,
    routing::{get, post},
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod handlers;

use handlers::auth;
use handlers::general;

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

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(general::health))
        // Auth routes
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/verify-email", get(auth::verify_email))
        // Swagger UI at root
        .merge(SwaggerUi::new("/").url("/api-docs/openapi.json", ApiDoc::openapi()));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("Server listening on http://0.0.0.0:3000");
    println!("API docs available at http://0.0.0.0:3000/");

    axum::serve(listener, app).await.expect("Server error");
}
