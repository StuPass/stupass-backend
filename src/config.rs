use std::env;
use tokio::sync::OnceCell;

#[derive(Debug)]
struct ServerConfig {
    host: String,
    port: u16,
    frontend_url: String, 
    server_url: String,
}

#[derive(Debug)]
struct DatabaseConfig {
    url: String,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry: i64,  // seconds
    pub refresh_token_expiry: i64, // seconds
}

#[derive(Debug)]
pub struct Config {
    server: ServerConfig,
    db: DatabaseConfig,
    jwt: JwtConfig,
    resend_api_key: String,
}

impl Config {
    pub fn db_url(&self) -> &str {
        &self.db.url
    }

    pub fn server_host(&self) -> &str {
        &self.server.host
    }

    pub fn server_port(&self) -> u16 {
        self.server.port
    }

    pub fn jwt(&self) -> &JwtConfig {
        &self.jwt
    }

    pub fn frontend_url(&self) -> &str {
        &self.server.frontend_url
    }
    
    pub fn server_url(&self) -> &str {
        &self.server.server_url
    }

    pub fn resend_api_key(&self) -> &str {
        &self.resend_api_key
    }
}

pub static CONFIG: OnceCell<Config> = OnceCell::const_new();

async fn init_config() -> Config {
    // Create a ServerConfig instance with default values or values from environment variables
    let server_config = ServerConfig {
        host: env::var("HOST").unwrap_or_else(|_| String::from("0.0.0.0")),
        port: env::var("PORT")
            .unwrap_or_else(|_| String::from("3000"))
            .parse::<u16>()
            .unwrap(),
        frontend_url: env::var("FRONTEND_URL")
            .unwrap_or_else(|_| String::from("stupass://")),
        server_url: env::var("SERVER_URL")
            .expect("SERVER_URL must be set"),
    };

    // Create a DatabaseConfig instance with a required DATABASE_URL environment variable
    let database_config = DatabaseConfig {
        url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
    };

    // Create a JwtConfig instance
    let jwt_config = JwtConfig {
        secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
        access_token_expiry: env::var("JWT_ACCESS_EXPIRY")
            .unwrap_or_else(|_| String::from("3600"))
            .parse::<i64>()
            .expect("JWT_ACCESS_EXPIRY must be a valid number"),
        refresh_token_expiry: env::var("JWT_REFRESH_EXPIRY")
            .unwrap_or_else(|_| String::from("604800"))
            .parse::<i64>()
            .expect("JWT_REFRESH_EXPIRY must be a valid number"),
    };

    let resend_api_key = env::var("RESEND_API_KEY").expect("RESEND_API_KEY must be set");

    Config {
        server: server_config,
        db: database_config,
        jwt: jwt_config,
        resend_api_key,
    }
}

pub async fn config() -> &'static Config {
    // Get the configuration from the OnceCell or initialize it if it hasn't been set yet
    CONFIG.get_or_init(init_config).await
}
