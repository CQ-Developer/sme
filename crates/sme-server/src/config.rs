//! Startup config comes entirely from environment variables; there is no config file.

use std::net::SocketAddr;

/// Gateway config.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address, default `127.0.0.1:8080` (set by compose in production).
    pub bind: SocketAddr,
    /// Postgres connection string.
    pub database_url: String,
    /// Valkey connection string, default `redis://127.0.0.1:6379`.
    pub valkey_url: String,
    /// D17 server HMAC key; generate with `openssl rand -hex 32` in production.
    pub hmac_key: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL 必须设置".to_string())?;
        let valkey_url =
            std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let hmac_key =
            std::env::var("SME_HMAC_KEY").map_err(|_| "SME_HMAC_KEY 必须设置".to_string())?;
        if hmac_key.len() < 16 {
            return Err("SME_HMAC_KEY 至少 16 字节".to_string());
        }

        let bind = std::env::var("SME_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let bind = bind
            .parse::<SocketAddr>()
            .map_err(|error| format!("SME_BIND_ADDR 无效: {error}"))?;

        Ok(Self {
            bind,
            database_url,
            valkey_url,
            hmac_key,
        })
    }
}
