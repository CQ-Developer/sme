//! sme 网关入口：读环境变量、连 Postgres 与 Valkey、跑迁移、启动自检、监听端口。

use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;

use sme_server::valkey::{Valkey, random_instance_id};
use sme_server::{app, config::Config, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::from_env().map_err(|error| format!("配置错误: {error}"))?;

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;

    // I7：队列组件必须禁用一切持久化，否则拒绝启动。
    let instance_id = random_instance_id().map_err(|error| error.to_string())?;
    let valkey = Valkey::connect(&config.valkey_url, config.hmac_key.as_bytes(), instance_id)
        .await
        .map_err(|error| format!("Valkey 启动自检失败: {error}"))?;

    let listener = TcpListener::bind(config.bind).await?;
    let addr = listener.local_addr()?;
    println!("sme-server listening on ws://{addr}");

    axum::serve(listener, app(AppState::new(pool, valkey))).await?;
    Ok(())
}
