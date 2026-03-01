#![allow(dead_code, unused_imports)]

mod db;
mod fixtures;
mod mock_email;
mod request;

pub use db::*;
pub use fixtures::*;
pub use mock_email::*;
pub use request::*;

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use stupass_backend::config::JwtConfig;
use stupass_backend::handlers::auth;
use stupass_backend::rate_limit::RateLimiter;
use stupass_backend::state::AppState;

/// Shared error response type for test assertions
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

/// Test context containing all test infrastructure
pub struct TestContext {
    pub db: DatabaseConnection,
    pub email_service: Arc<MockEmailService>,
    pub state: AppState,
}

impl TestContext {
    /// Create a new test context with in-memory database
    pub async fn new() -> Self {
        let db = setup_test_db().await;
        let email_service = Arc::new(MockEmailService::new());

        let state = AppState::builder()
            .db(db.clone())
            .jwt(JwtConfig {
                secret: "test-secret-key-for-testing-only".to_string(),
                access_token_expiry: 3600,
                refresh_token_expiry: 604800,
            })
            .email_service(email_service.clone())
            .fe_url("http://localhost:3000".to_string())
            .server_url("http://localhost:8080".to_string())
            .rate_limiter(RateLimiter::new())
            .build();

        Self {
            db,
            email_service,
            state,
        }
    }

    /// Clear all test data between tests
    pub async fn cleanup(&self) {
        cleanup_db(&self.db).await;
        self.email_service.clear();
    }
}
