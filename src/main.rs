use axum::{routing::get, Router, Json};
use sea_orm::{Database, DatabaseConnection};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer; // NEW: Logging middleware
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> { // NEW: anyhow::Result for clean errors
    // 1. Load .env file
    dotenvy::dotenv().ok();

    // 2. Setup Tracing & Tokio Console
    // "RUST_LOG=debug" triggers detailed logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "backend_service=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Note: To use tokio-console, replace the block above with:
    // console_subscriber::init(); 
    // (Cannot use both fmt::layer and console_subscriber easily without complex setup)

    // 3. Database Connection
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_owned());
    let db: DatabaseConnection = Database::connect(db_url).await?;

    let state = AppState { db };

    // 4. Router with Middleware
    let app = Router::new()
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http()) // NEW: Logs every request
        .with_state(state);

    // 5. Bind & Serve
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}
