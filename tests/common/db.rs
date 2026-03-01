#![allow(dead_code, unused_imports)]

use migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};

use stupass_backend::entities::auth_provider;

/// Creates an in-memory SQLite database with migrations applied
pub async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to test database");

    Migrator::up(&db, None)
        .await
        .expect("Failed to run migrations");

    // Seed required auth provider
    seed_auth_provider(&db).await;

    db
}

async fn seed_auth_provider(db: &DatabaseConnection) {
    let provider = auth_provider::ActiveModel {
        id: sea_orm::ActiveValue::Set(1),
        name: sea_orm::ActiveValue::Set("Password".to_string()),
    };

    use sea_orm::ActiveModelTrait;
    provider.insert(db).await.ok(); // Ignore if exists
}

/// Clears all tables between tests
pub async fn cleanup_db(db: &DatabaseConnection) {
    // Delete in dependency order using raw SQL for simplicity
    use sea_orm::ConnectionTrait;

    db.execute_unprepared("DELETE FROM password_reset_token")
        .await
        .ok();
    db.execute_unprepared("DELETE FROM session").await.ok();
    db.execute_unprepared("DELETE FROM credential").await.ok();
    db.execute_unprepared("DELETE FROM user").await.ok();
}
