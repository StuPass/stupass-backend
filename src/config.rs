use std::env;
use dotenvy::dotenv;
use tokio::sync::OnceCell;

#[derive(Debug)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Debug)]
struct DatabaseConfig {
    url: String,
}

#[derive(Debug)]
pub struct Config {
    server: ServerConfig,
    db: DatabaseConfig,
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
}

pub static CONFIG: OnceCell<Config> = OnceCell::const_new();

async fn init_config() -> Config {
    // Load environment variables from a .env file if present
    dotenv().ok();

    // Create a ServerConfig instance with default values or values from environment variables
    let server_config = ServerConfig {
        host: env::var("HOST").unwrap_or_else(|_| String::from("127.0.0.1")),
        port: env::var("PORT")
            .unwrap_or_else(|_| String::from("3000"))
            .parse::<u16>()
            .unwrap(),
    };

    // Create a DatabaseConfig instance with a required DATABASE_URL environment variable
    let database_config = DatabaseConfig {
        url: env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
    };

    // Create a Config instance by combining server and database configurations
    Config {
        server: server_config,
        db: database_config,
    }
}

pub async fn config() -> &'static Config {
    // Get the configuration from the OnceCell or initialize it if it hasn't been set yet
    CONFIG.get_or_init(init_config).await
}