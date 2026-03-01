use axum::{
    Router,
    http::StatusCode,
    middleware,
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

use stupass_backend::config::build_config;
use stupass_backend::handlers::auth;
use stupass_backend::handlers::general;
use stupass_backend::middleware::auth_middleware::auth_middleware;
use stupass_backend::models;
use stupass_backend::rate_limit::RateLimiter;
use stupass_backend::services::email::ResendEmailService;
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
        auth::resend_verification,
        auth::check_status,
    ),
    components(schemas(
        models::auth::RegisterRequest,
        models::auth::LoginRequest,
        models::auth::LogoutRequest,
        models::auth::RefreshRequest,
        models::auth::ForgotPasswordRequest,
        models::auth::ResetPasswordRequest,
        models::auth::ResendVerificationRequest,
        models::auth::TokenQuery,
        models::auth::AuthTokens,
        models::auth::RegisterResponse,
        models::auth::LoginResponse,
        models::auth::LogoutResponse,
        models::auth::RefreshResponse,
        models::auth::ForgotPasswordResponse,
        models::auth::ResetPasswordResponse,
        models::auth::VerifyEmailResponse,
        models::auth::CheckStatusResponse,
        models::auth::BadRequest,
        models::auth::Unauthorized,
        models::auth::Conflict,
    )),
    tags(
        (name = "general", description = "General endpoints"),
        (name = "auth", description = "Authentication endpoints"),
    ),
    // This tells Swagger that endpoints marked with security use a Bearer token
    modifiers(&SecurityAddon),
)]
struct ApiDoc;

// Helper to add Bearer Auth to Swagger UI
struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            )
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    init_tracing();

    let app_config = build_config().await;

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

    let rate_limiter = RateLimiter::new();

    let state = AppState {
        db,
        jwt: app_config.jwt().clone(),
        email_service,
        fe_url: app_config.frontend_url().to_string(),
        server_url: app_config.server_url().to_string(),
        rate_limiter,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION, ACCEPT]);

    let public_routes = Router::new()
        .route("/health", get(general::health))
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/auth/verify-email", get(auth::verify_email))
        .route("/auth/resend-verification", post(auth::resend_verification))
        .route("/auth/check-status/{user_id}", get(auth::check_status));

    let protected_routes = Router::new()
        .route("/auth/logout", post(auth::logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .fallback(handler_404)
        .with_state(state)
        .merge(SwaggerUi::new("/").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(cors);

    let host = app_config.listen_host();
    let port = app_config.listen_port();
    let address = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = address.parse().expect("Unable to parse socket address");

    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!("Server listening on http://{}", socket_addr);
    tracing::info!("API docs available at http://{}/", socket_addr);

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
