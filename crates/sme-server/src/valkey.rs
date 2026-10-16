//! Valkey 访问层（D9、D17、D7、docs/INFRA.md §4）。
//!
//! - 所有键名与频道名里含账号的部分，一律换成 `HMAC-SHA256(服务端密钥, 账号ID)`
//!   的前 32 个十六进制字符（D17）：运维看不到谁在等谁的消息。
//! - 密文只进 Stream 与图片兄弟键；Stream 条目按时间裁剪，TTL 24h（D7）。
//! - 启动自检（I7）：`save` 非空 / `appendonly yes` / 非 `noeviction` 直接拒绝启动。
//! - 挑战、presence、预密钥、限流也都在这里，网关本身保持无状态。

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use redis::aio::{ConnectionManager, PubSub};
use sha2::Sha256;
use sme_proto::{AccountId, PreKeyUpload};

type HmacSha256 = Hmac<Sha256>;

/// 密文队列 TTL（D7）。
pub const QUEUE_TTL_SECS: u64 = 24 * 60 * 60;

/// 每个收件人的队列长度上限（D7）。
pub const MAX_QUEUE_LEN: i64 = 100;

/// 一次性预密钥 TTL（docs/INFRA.md §4.1）。
pub const PREKEY_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// 登录挑战 TTL。
pub const CHALLENGE_TTL_SECS: u64 = 60;

/// presence TTL；网关心跳每 20s 续期。
pub const PRESENCE_TTL_SECS: u64 = 60;

const PUSH_SCRIPT: &str = r#"
local id = redis.call('XADD', KEYS[1], 'MAXLEN', '~', ARGV[2], '*', 'e', ARGV[1])
redis.call('XTRIM', KEYS[1], 'MINID', ARGV[3])
return id
"#;

const ACK_SCRIPT: &str = r#"
redis.call('XDEL', KEYS[1], ARGV[1])
redis.call('DEL', KEYS[2])
return 1
"#;

const TAKE_PREKEY_SCRIPT: &str = r#"
local keys = redis.call('HKEYS', KEYS[1])
if #keys == 0 then return nil end
local id = keys[1]
local value = redis.call('HGET', KEYS[1], id)
redis.call('HDEL', KEYS[1], id)
return {id, value}
"#;

const PRESENCE_TAKE_SCRIPT: &str = r#"
local previous = redis.call('GET', KEYS[1])
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return previous
"#;

const PRESENCE_REFRESH_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current or current == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
    return 1
end
return 0
"#;

const PRESENCE_CLEAR_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"#;

const RATE_LIMIT_SCRIPT: &str = r#"
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return count
"#;

#[derive(Debug)]
pub enum ValkeyError {
    Redis(redis::RedisError),
    NotEphemeral(String),
    BadValue(&'static str),
    RandomSource,
}

impl std::fmt::Display for ValkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redis(error) => write!(f, "valkey error: {error}"),
            Self::NotEphemeral(detail) => write!(
                f,
                "Valkey 必须禁用持久化（save=\"\"、appendonly no、noeviction），当前 {detail}"
            ),
            Self::BadValue(what) => write!(f, "valkey reply has an invalid {what}"),
            Self::RandomSource => write!(f, "OS random source unavailable"),
        }
    }
}

impl std::error::Error for ValkeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Redis(error) => Some(error),
            _ => None,
        }
    }
}

impl From<redis::RedisError> for ValkeyError {
    fn from(error: redis::RedisError) -> Self {
        Self::Redis(error)
    }
}

/// 网关的 Valkey 句柄；可以随意 clone（内部是重连管理器）。
#[derive(Clone)]
pub struct Valkey {
    client: redis::Client,
    connection: ConnectionManager,
    hmac_key: Arc<[u8]>,
    instance_id: Arc<str>,
}

impl Valkey {
    /// 连接并立刻执行 I7 启动自检；不满足就返回错误（网关拒绝启动）。
    pub async fn connect(
        url: &str,
        hmac_key: &[u8],
        instance_id: String,
    ) -> Result<Self, ValkeyError> {
        let client = redis::Client::open(url)?;
        let connection = ConnectionManager::new(client.clone()).await?;
        let valkey = Self {
            client,
            connection,
            hmac_key: Arc::from(hmac_key),
            instance_id: instance_id.into(),
        };
        valkey.verify_ephemeral().await?;
        Ok(valkey)
    }

    /// I7：`save` 必须为空字符串、`appendonly` 必须为 `no`、驱逐策略必须是 `noeviction`。
    pub async fn verify_ephemeral(&self) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let values: Vec<String> = redis::cmd("CONFIG")
            .arg("GET")
            .arg("save")
            .arg("appendonly")
            .arg("maxmemory-policy")
            .query_async(&mut connection)
            .await?;

        let mut save = None;
        let mut appendonly = None;
        let mut policy = None;
        for pair in values.chunks(2) {
            match pair.first().map(String::as_str) {
                Some("save") => save = pair.get(1).cloned(),
                Some("appendonly") => appendonly = pair.get(1).cloned(),
                Some("maxmemory-policy") => policy = pair.get(1).cloned(),
                _ => {}
            }
        }

        if !save.as_deref().unwrap_or("").is_empty() {
            return Err(ValkeyError::NotEphemeral(format!("save = {save:?}")));
        }
        if appendonly.as_deref() != Some("no") {
            return Err(ValkeyError::NotEphemeral(format!(
                "appendonly = {appendonly:?}"
            )));
        }
        if policy.as_deref() != Some("noeviction") {
            return Err(ValkeyError::NotEphemeral(format!(
                "maxmemory-policy = {policy:?}"
            )));
        }
        Ok(())
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// D17：`HMAC-SHA256(服务端密钥, 账号ID)` 的前 32 个十六进制字符。
    pub fn hmac_account(&self, account: AccountId) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC 接受任意长度密钥");
        mac.update(account.as_bytes());
        let digest = mac.finalize().into_bytes();
        to_hex(&digest[..16])
    }

    /// 账号的唤醒频道名。
    pub fn channel(&self, account: AccountId) -> String {
        format!("gw:{}", self.hmac_account(account))
    }

    fn queue_key(&self, account: AccountId) -> String {
        format!("q:{}", self.hmac_account(account))
    }

    fn image_key(&self, account: AccountId, entry_id: &str) -> String {
        format!("img:{}:{entry_id}", self.hmac_account(account))
    }

    fn presence_key(&self, account: AccountId) -> String {
        format!("p:{}", self.hmac_account(account))
    }

    fn prekey_key(&self, account: AccountId) -> String {
        format!("pk:{}", self.hmac_account(account))
    }

    /// 入队一条密文；返回 Stream 条目 ID（客户端用它做 D-ack）。
    pub async fn enqueue(&self, to: AccountId, envelope: &[u8]) -> Result<String, ValkeyError> {
        let mut connection = self.connection.clone();
        let min_id = now_millis().saturating_sub(QUEUE_TTL_SECS * 1000);

        let entry_id: String = redis::Script::new(PUSH_SCRIPT)
            .key(self.queue_key(to))
            .arg(envelope)
            .arg(MAX_QUEUE_LEN)
            .arg(min_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(entry_id)
    }

    /// D-ack：原子删除队列条目与图片兄弟键。
    pub async fn ack(&self, account: AccountId, entry_id: &str) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: i64 = redis::Script::new(ACK_SCRIPT)
            .key(self.queue_key(account))
            .key(self.image_key(account, entry_id))
            .arg(entry_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 读取该收件人全部未 D-ack 的条目（条目 ID + 信封字节）。
    pub async fn queued(&self, account: AccountId) -> Result<Vec<(String, Vec<u8>)>, ValkeyError> {
        let mut connection = self.connection.clone();
        let value: redis::Value = redis::cmd("XRANGE")
            .arg(self.queue_key(account))
            .arg("-")
            .arg("+")
            .query_async(&mut connection)
            .await?;
        parse_stream_entries(value)
    }

    /// 唤醒持有该账号连接的网关；`payload` 是 Stream 条目 ID 或 `"k"`（顶替旧会话）。
    pub async fn publish(&self, account: AccountId, payload: &str) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: i64 = redis::cmd("PUBLISH")
            .arg(self.channel(account))
            .arg(payload)
            .query_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 订阅某个账号的唤醒频道。
    pub async fn subscribe(&self, account: AccountId) -> Result<PubSub, ValkeyError> {
        let mut pubsub = self.client.get_async_pubsub().await?;
        pubsub.subscribe(self.channel(account)).await?;
        Ok(pubsub)
    }

    /// 上传一次性预密钥（Hash，TTL 7 天）；返回服务端保存的总数。
    pub async fn store_prekeys(
        &self,
        account: AccountId,
        prekeys: &[PreKeyUpload],
    ) -> Result<u64, ValkeyError> {
        let mut connection = self.connection.clone();
        let key = self.prekey_key(account);

        if !prekeys.is_empty() {
            let mut command = redis::cmd("HSET");
            command.arg(&key);
            for prekey in prekeys {
                command.arg(&prekey.key_id).arg(to_hex(&prekey.public_key));
            }
            let _: i64 = command.query_async(&mut connection).await?;
            let _: i64 = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(PREKEY_TTL_SECS)
                .query_async(&mut connection)
                .await?;
        }

        let stored: i64 = redis::cmd("HLEN")
            .arg(&key)
            .query_async(&mut connection)
            .await?;
        Ok(stored.max(0) as u64)
    }

    /// 取走一条一次性预密钥（取出即删）。
    pub async fn take_prekey(
        &self,
        account: AccountId,
    ) -> Result<Option<PreKeyUpload>, ValkeyError> {
        let mut connection = self.connection.clone();
        let taken: Option<(String, String)> = redis::Script::new(TAKE_PREKEY_SCRIPT)
            .key(self.prekey_key(account))
            .invoke_async(&mut connection)
            .await?;

        let Some((key_id, public_hex)) = taken else {
            return Ok(None);
        };
        let public_key =
            from_hex32(&public_hex).ok_or(ValkeyError::BadValue("prekey public key"))?;
        Ok(Some(PreKeyUpload { key_id, public_key }))
    }

    /// 保存登录挑战：`nonce → h(account)`，60s 过期。
    pub async fn set_challenge(
        &self,
        nonce: &[u8; 32],
        account_hash: &str,
    ) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: () = redis::cmd("SET")
            .arg(challenge_key(nonce))
            .arg(account_hash)
            .arg("EX")
            .arg(CHALLENGE_TTL_SECS)
            .query_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 一次性读取并删除挑战。
    pub async fn take_challenge(&self, nonce: &[u8; 32]) -> Result<Option<String>, ValkeyError> {
        let mut connection = self.connection.clone();
        let value: Option<String> = redis::cmd("GETDEL")
            .arg(challenge_key(nonce))
            .query_async(&mut connection)
            .await?;
        Ok(value)
    }

    /// 登录时接管 presence；返回之前的实例 ID（用于踢旧网关的连接）。
    pub async fn take_presence(&self, account: AccountId) -> Result<Option<String>, ValkeyError> {
        let mut connection = self.connection.clone();
        let previous: Option<String> = redis::Script::new(PRESENCE_TAKE_SCRIPT)
            .key(self.presence_key(account))
            .arg(self.instance_id.as_ref())
            .arg(PRESENCE_TTL_SECS)
            .invoke_async(&mut connection)
            .await?;
        Ok(previous)
    }

    /// 心跳续期：只有 presence 仍属于本实例时才续（否则说明已被新登录顶替）。
    pub async fn refresh_presence(&self, account: AccountId) -> Result<bool, ValkeyError> {
        let mut connection = self.connection.clone();
        let refreshed: i64 = redis::Script::new(PRESENCE_REFRESH_SCRIPT)
            .key(self.presence_key(account))
            .arg(self.instance_id.as_ref())
            .arg(PRESENCE_TTL_SECS)
            .invoke_async(&mut connection)
            .await?;
        Ok(refreshed == 1)
    }

    /// 断开时清理 presence，仅当它仍属于本实例。
    pub async fn clear_presence(&self, account: AccountId) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: i64 = redis::Script::new(PRESENCE_CLEAR_SCRIPT)
            .key(self.presence_key(account))
            .arg(self.instance_id.as_ref())
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// 固定窗口限流：窗口内计数不超过 `limit` 时返回 `true`。
    pub async fn check_rate_limit(
        &self,
        scope: &str,
        account: AccountId,
        limit: u64,
        window_secs: u64,
    ) -> Result<bool, ValkeyError> {
        let mut connection = self.connection.clone();
        let window = now_millis() / (window_secs * 1000).max(1);
        let key = format!("rl:{scope}:{}:{window}", self.hmac_account(account));
        let count: i64 = redis::Script::new(RATE_LIMIT_SCRIPT)
            .key(key)
            .arg(window_secs)
            .invoke_async(&mut connection)
            .await?;
        Ok(count.max(0) as u64 <= limit)
    }

    /// `/stats` 用的聚合值：键总数（只有数量，不含任何内容）。
    pub async fn dbsize(&self) -> Result<u64, ValkeyError> {
        let mut connection = self.connection.clone();
        let size: i64 = redis::cmd("DBSIZE").query_async(&mut connection).await?;
        Ok(size.max(0) as u64)
    }
}

/// 生成网关实例 ID（presence 与顶替判断用）。
pub fn random_instance_id() -> Result<String, ValkeyError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| ValkeyError::RandomSource)?;
    Ok(to_hex(&bytes))
}

fn challenge_key(nonce: &[u8; 32]) -> String {
    format!("ch:{}", to_hex(nonce))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn from_hex32(input: &str) -> Option<[u8; 32]> {
    if input.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in input.as_bytes().chunks(2).enumerate() {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// XRANGE 原始回复 → (条目 ID, 信封字节)。
fn parse_stream_entries(value: redis::Value) -> Result<Vec<(String, Vec<u8>)>, ValkeyError> {
    let redis::Value::Array(rows) = value else {
        return Err(ValkeyError::BadValue("XRANGE reply"));
    };

    let mut entries = Vec::new();
    for row in rows {
        let redis::Value::Array(parts) = row else {
            continue;
        };
        if parts.len() < 2 {
            continue;
        }
        let redis::Value::BulkString(id) = &parts[0] else {
            continue;
        };
        let redis::Value::Array(fields) = &parts[1] else {
            continue;
        };
        let [
            redis::Value::BulkString(name),
            redis::Value::BulkString(payload),
            ..,
        ] = fields.as_slice()
        else {
            continue;
        };
        if name == b"e" {
            entries.push((String::from_utf8_lossy(id).into_owned(), payload.clone()));
        }
    }
    Ok(entries)
}
