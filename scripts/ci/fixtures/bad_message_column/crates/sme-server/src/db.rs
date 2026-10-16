//! I1 反例（Rust 内联 SQL 路径）：门禁必须挡住字符串字面量里的 payload。

pub async fn bad(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT payload FROM accounts").fetch_all(pool).await;
}
