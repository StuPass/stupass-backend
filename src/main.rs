use tracing_subscriber::prelude::*;
use sea_orm::Database;
use migration::{Migrator, MigratorTrait};
use std::net::SocketAddr;
use dotenvy::dotenv;

use stupass_backend::state::AppState;
use stupass_backend::config::config;
use stupass_backend::routes::app_router;

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

    let state = AppState { db };

    let app = app_router(state.clone());

    let host = app_config.server_host();
    let port = app_config.server_port();
    let address = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = address.parse().expect("Unable to parse socket address");

    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .expect("Failed to bind to address");

    tracing::info!("Server listening on http://127.0.0.1:3000 (http://{})", socket_addr);
    tracing::info!("API docs available at http://127.0.0.1:3000/");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

// Function to initialize tracing
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "info,stupass_backend=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}