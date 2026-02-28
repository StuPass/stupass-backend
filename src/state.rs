use std::sync::Arc;

use axum::extract::FromRef;
use sea_orm::DatabaseConnection;

use crate::config::JwtConfig;
use crate::rate_limit::RateLimiter;
use crate::services::EmailService;
use crate::services::auth::AuthDeps;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt: JwtConfig,
    pub email_service: Arc<dyn EmailService>,
    pub fe_url: String,
    pub server_url: String,
    pub rate_limiter: RateLimiter,
}

#[derive(Clone)]
pub struct AuthState {
    pub db: DatabaseConnection,
    pub jwt: JwtConfig,
    pub email_service: Arc<dyn EmailService>,
    pub fe_url: String,
    pub server_url: String,
    pub rate_limiter: RateLimiter,
}

impl AuthDeps for AuthState {
    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    fn jwt(&self) -> &JwtConfig {
        &self.jwt
    }

    fn email_service(&self) -> &dyn EmailService {
        self.email_service.as_ref()
    }

    fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    fn fe_url(&self) -> &str {
        &self.fe_url
    }

    fn server_url(&self) -> &str {
        &self.server_url
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(app_state: &AppState) -> Self {
        Self {
            db: app_state.db.clone(),
            jwt: app_state.jwt.clone(),
            email_service: app_state.email_service.clone(),
            fe_url: app_state.fe_url.clone(),
            server_url: app_state.server_url.clone(),
            rate_limiter: app_state.rate_limiter.clone(),
        }
    }
}

/// Builder for creating AppState instances (useful for testing)
#[derive(Default)]
pub struct AppStateBuilder {
    db: Option<DatabaseConnection>,
    jwt: Option<JwtConfig>,
    email_service: Option<Arc<dyn EmailService>>,
    fe_url: Option<String>,
    server_url: Option<String>,
    rate_limiter: Option<RateLimiter>,
}

impl AppStateBuilder {
    pub fn db(mut self, db: DatabaseConnection) -> Self {
        self.db = Some(db);
        self
    }

    pub fn jwt(mut self, jwt: JwtConfig) -> Self {
        self.jwt = Some(jwt);
        self
    }

    pub fn email_service(mut self, service: Arc<dyn EmailService>) -> Self {
        self.email_service = Some(service);
        self
    }

    pub fn fe_url(mut self, url: String) -> Self {
        self.fe_url = Some(url);
        self
    }

    pub fn server_url(mut self, url: String) -> Self {
        self.server_url = Some(url);
        self
    }

    pub fn rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    pub fn build(self) -> AppState {
        AppState {
            db: self.db.expect("db is required"),
            jwt: self.jwt.expect("jwt is required"),
            email_service: self.email_service.expect("email_service is required"),
            fe_url: self.fe_url.unwrap_or_default(),
            server_url: self.server_url.unwrap_or_default(),
            rate_limiter: self.rate_limiter.unwrap_or_default(),
        }
    }
}

impl AppState {
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::default()
    }
}
