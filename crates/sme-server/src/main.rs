//! sme 网关入口：读环境变量、连 Postgres、跑迁移、监听端口。

use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

use sme_server::{app, config::Config, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env().map_err(|error| format!("配置错误: {error}"))?;

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    let listener = TcpListener::bind(config.bind).await?;
    println!("sme-server listening on ws://{}", config.bind);

    axum::serve(listener, app(AppState::new(pool))).await?;
    Ok(())
}
