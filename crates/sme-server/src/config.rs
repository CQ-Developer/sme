//! 启动配置：全部来自环境变量，无配置文件。

use std::net::SocketAddr;

/// 网关配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// 监听地址，默认 `127.0.0.1:8080`（生产由 compose 指定）。
    pub bind: SocketAddr,
    /// Postgres 连接串。
    pub database_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL 必须设置".to_string())?;

        let bind = std::env::var("SME_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let bind = bind
            .parse::<SocketAddr>()
            .map_err(|error| format!("SME_BIND_ADDR 无效: {error}"))?;

        Ok(Self { bind, database_url })
    }
}
