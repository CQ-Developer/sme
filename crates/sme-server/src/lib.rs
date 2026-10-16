//! sme gateway (M3): register, challenge-signature login, prekey distribution and ciphertext relay.
//!
//! The server reads only routing fields (`from` / `to` / `sid`) and forwards `payload` untouched,
//! Never parsed, never persisted, never logged. Persistence is just the `accounts` table (I1);
//! Queues, prekeys, challenges, presence and rate limits all live in Valkey (D9, D17).

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

/// Assemble the HTTP / WebSocket routes.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/ws", get(ws::ws_handler))
        .with_state(state)
}

/// Process liveness probe; returns a fixed string and exposes no runtime data.
async fn healthz() -> &'static str {
    "ok"
}

/// Aggregate read-only metrics for debugging; **no content and no per-account information**.
async fn stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let valkey_keys = state.valkey.dbsize().await.unwrap_or(0);
    Json(json!({
        "connections": state.connection_count(),
        "forwarded": state.forwarded(),
        "rejected": state.rejected(),
        "valkey_keys": valkey_keys,
    }))
}
