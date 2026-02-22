use sea_orm::DatabaseConnection;

use crate::config::JwtConfig;

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt: JwtConfig,
}