use tracing_subscriber::prelude::*;
use sea_orm::Database;
use migration::{Migrator, MigratorTrait};

// Modules
use stupass_backend::config::config;
use stupass_backend::state::AppState;

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
