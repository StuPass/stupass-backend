use sea_orm::DatabaseConnection;

use crate::config::JwtConfig;

#[derive(Clone, Debug)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt: JwtConfig,
    pub http_client: reqwest::Client,
    pub resend_api_key: String,
    pub fe_url: String,
    pub server_url: String,
}
