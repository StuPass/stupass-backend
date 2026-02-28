use crate::{config::JwtConfig, rate_limit::RateLimiter, services::EmailService};
use sea_orm::DatabaseConnection;

pub mod login;
pub mod password;
pub mod register;
pub mod session;

// Trait abstraction for Auth functional modules dependency injection
pub trait AuthDeps: Send + Sync {
    fn db(&self) -> &DatabaseConnection;
    fn jwt(&self) -> &JwtConfig;
    fn email_service(&self) -> &dyn EmailService;
    fn rate_limiter(&self) -> &RateLimiter;
    fn fe_url(&self) -> &str;
    fn server_url(&self) -> &str;
}
