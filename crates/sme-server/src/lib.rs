//! sme 网关（M2）：注册、挑战-签名登录、预密钥分发与密文转发。
//!
//! 服务端只读信封的路由字段（`from` / `to` / `sid`），`payload` 一律原样转发，
//! 不解析、不落盘、不写日志。持久层只有 `accounts` 表（I1）。

pub mod config;
pub mod db;
pub mod state;
pub mod ws;

use axum::Router;
use axum::routing::get;

use crate::state::AppState;

/// 组装 HTTP / WebSocket 路由。
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}

/// 进程存活探针；只返回固定字符串，不暴露任何运行数据。
async fn healthz() -> &'static str {
    "ok"
}
