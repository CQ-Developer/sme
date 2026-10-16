//! I1 counter-example (inline SQL path): the gate must block `payload` inside a string literal.

pub async fn bad(pool: &sqlx::PgPool) {
    let _ = sqlx::query("SELECT payload FROM accounts").fetch_all(pool).await;
}
