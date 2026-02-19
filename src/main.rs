use axum::{
    Router,
    routing::{get, post},
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tracing_subscriber::prelude::*;
use sea_orm::Database;
use migration::{Migrator, MigratorTrait};

use stupass_backend::handlers::auth;
use stupass_backend::handlers::general;
use stupass_backend::config::config;
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
    init_tracing();

    let app_config = config().await;

    let db = Database::connect(app_config.db_url())
        .await
        .expect("Failed to connect to database");

    if let Err(err) = Migrator::up(&db, None).await {
        tracing::error!("Failed to run migrations: {:?}", err);
        return;
    }

    let state = AppState { db };

    print!("{:?}", state);

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

    println!("Server listening on http://127.0.0.1:3000 (http://0.0.0.0:3000)");
    println!("API docs available at http://127.0.0.1:3000/");

    axum::serve(listener, app).await.expect("Server error");
>>>>>>> main
}

// Function to initialize tracing
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "example_tokio_postgres=debug,axum_diesel_real_world=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}