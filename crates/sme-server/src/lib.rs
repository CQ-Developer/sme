//! sme 网关（M3）：注册、挑战-签名登录、预密钥分发与密文转发。
//!
//! 服务端只读信封的路由字段（`from` / `to` / `sid`），`payload` 一律原样转发，
//! 不解析、不落盘、不写日志。持久层只有 `accounts` 表（I1）；
//! 队列、预密钥、挑战、presence 与限流都在 Valkey（D9、D17）。

pub mod config;
pub mod db;
pub mod state;
pub mod valkey;
pub mod ws;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::get;
use serde_json::json;

use crate::state::AppState;

/// 组装 HTTP / WebSocket 路由。
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}

/// 进程存活探针；只返回固定字符串，不暴露任何运行数据。
async fn healthz() -> &'static str {
    "ok"
}

/// 聚合只读指标，供排障用；**不含任何内容或账号级信息**。
async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let valkey_keys = state.valkey.dbsize().await.unwrap_or(0);
    Json(json!({
        "connections": state.connection_count(),
        "forwarded": state.forwarded(),
        "rejected": state.rejected(),
        "valkey_keys": valkey_keys,
    }))
}
