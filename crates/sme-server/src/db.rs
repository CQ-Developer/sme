//! 账号持久层：唯一业务表 `accounts`（docs/INFRA.md §3）。
//!
//! 查询用运行时的 `query_as`（D25 方案 A）；字段名门禁与迁移审查（I1）兜底。

use sme_proto::{AccountId, Registration};
use sqlx::PgPool;

/// 从 `accounts` 读出的身份公钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredAccount {
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
}

/// 注册一个账号；已存在时返回 `false`（不覆盖任何字段）。
pub async fn insert_account(
    pool: &PgPool,
    registration: &Registration,
) -> Result<bool, sqlx::Error> {
    let kdf_params = serde_json::json!({
        "alg": "argon2id",
        "v": 19,
        "m_cost": registration.kdf_params.m_cost,
        "t_cost": registration.kdf_params.t_cost,
        "p_cost": registration.kdf_params.p_cost,
    });

    let result = sqlx::query(
        "INSERT INTO accounts (account_id, ed25519_pub, curve25519_pub, kdf_salt, kdf_params)
         VALUES ($1, $2, $3, $4, $5::jsonb)
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind(registration.account_id.to_base32())
    .bind(registration.ed25519_pub.as_slice())
    .bind(registration.curve25519_pub.as_slice())
    .bind(registration.kdf_salt.as_slice())
    .bind(kdf_params.to_string())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}

/// 读取账号身份公钥；不存在或数据长度异常时返回 `None`。
pub async fn load_account(
    pool: &PgPool,
    account_id: AccountId,
) -> Result<Option<StoredAccount>, sqlx::Error> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT ed25519_pub, curve25519_pub FROM accounts WHERE account_id = $1")
            .bind(account_id.to_base32())
            .fetch_optional(pool)
            .await?;

    Ok(row.and_then(|(ed25519, curve25519)| {
        Some(StoredAccount {
            ed25519_pub: ed25519.try_into().ok()?,
            curve25519_pub: curve25519.try_into().ok()?,
        })
    }))
}
