use axum::{
    Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use dotenvy::dotenv;
use http::Method;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use migration::{Migrator, MigratorTrait};
use reqwest::Client;
use sea_orm::Database;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::prelude::*;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use stupass_backend::config::config;
use stupass_backend::handlers::auth;
use stupass_backend::handlers::general;
use stupass_backend::models;
use stupass_backend::rate_limit::RateLimiter;
use stupass_backend::services::{auth::service::AuthServiceImpl, email::ResendEmailService};
use stupass_backend::state::AppState;

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
        models::auth::RegisterRequest,
        models::auth::LoginRequest,
        models::auth::LogoutRequest,
        models::auth::RefreshRequest,
        models::auth::ForgotPasswordRequest,
        models::auth::ResetPasswordRequest,
        models::auth::TokenQuery,
        models::auth::AuthTokens,
        models::auth::RegisterResponse,
        models::auth::LoginResponse,
        models::auth::LogoutResponse,
        models::auth::RefreshResponse,
        models::auth::ForgotPasswordResponse,
        models::auth::ResetPasswordResponse,
        models::auth::VerifyEmailResponse,
        models::auth::BadRequest,
        models::auth::Unauthorized,
        models::auth::Conflict,
    )),
    tags(
        (name = "general", description = "General endpoints"),
        (name = "auth", description = "Authentication endpoints"),
    ),
)]
struct ApiDoc;

#[tokio::main]
async fn main() {
    dotenv().ok();

    init_tracing();

    let app_config = config().await;

    let db = Database::connect(app_config.db_url())
        .await
        .expect("Failed to connect to database");

    if let Err(err) = Migrator::up(&db, None).await {
        tracing::error!("Failed to run migrations: {:?}", err);
        return;
    }

    let email_service = Arc::new(ResendEmailService::new(
        Client::new(),
        app_config.resend_api_key().to_string(),
    ));

    let auth_service = Arc::new(AuthServiceImpl);

    let state = AppState {
        db,
        jwt: app_config.jwt().clone(),
        email_service,
        auth_service,
        fe_url: app_config.frontend_url().to_string().clone(),
        server_url: app_config.server_url().to_string().clone(),
        rate_limiter: RateLimiter::new(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION, ACCEPT]);

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
        .fallback(handler_404)
        .with_state(state)
        // Swagger UI at root
        .merge(SwaggerUi::new("/").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(cors);

    let host = app_config.server_host();
    let port = app_config.server_port();
    let address = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = address.parse().expect("Unable to parse socket address");

    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!(
        "Server listening on http://127.0.0.1:3000 (http://{})",
        socket_addr
    );
    tracing::info!("API docs available at http://127.0.0.1:3000/");

    axum::serve(listener, app).await.expect("Server error");
}

// Function to initialize tracing
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,stupass_backend=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

// Handler for 404 Not Found errors
async fn handler_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        "The requested resource was not found",
    )
}
