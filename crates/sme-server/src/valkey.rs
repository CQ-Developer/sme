//! Valkey access layer (D9, D17, D7, docs/INFRA.md §4).
//!
//! - Every account part of a key or channel name is replaced by `HMAC-SHA256(server key, account ID)`
//!   the first 32 hex characters (D17): operators cannot see who is waiting for whose messages.
//! - Ciphertext goes only into Streams and image sibling keys; stream entries are trimmed by age with a 24h TTL (D7).
//! - Startup self-check (I7): a non-empty `save`, `appendonly yes`, or a policy other than `noeviction` refuses startup.
//! - Challenges, presence, prekeys and rate limits live here too, keeping the gateway stateless.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use redis::aio::{ConnectionManager, PubSub};
use sha2::Sha256;
use sme_proto::{AccountId, PreKeyUpload};

type HmacSha256 = Hmac<Sha256>;

/// Ciphertext queue TTL (D7).
pub const QUEUE_TTL_SECS: u64 = 24 * 60 * 60;

/// Maximum queue length per recipient (D7).
pub const MAX_QUEUE_LEN: i64 = 100;

/// One-time prekey TTL (docs/INFRA.md §4.1).
pub const PREKEY_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Login challenge TTL.
pub const CHALLENGE_TTL_SECS: u64 = 60;

/// Presence TTL; the gateway heartbeat refreshes it every 20s.
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

/// Gateway Valkey handle; cheap to clone (a reconnecting manager inside).
#[derive(Clone)]
pub struct Valkey {
    client: redis::Client,
    connection: ConnectionManager,
    hmac_key: Arc<[u8]>,
    instance_id: Arc<str>,
}

impl Valkey {
    /// Connect and run the I7 startup self-check immediately; an error here refuses gateway startup.
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

    /// I7: `save` must be empty, `appendonly` must be `no`, and the eviction policy must be `noeviction`.
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

    /// D17: the first 32 hex characters of `HMAC-SHA256(server key, account ID)`.
    pub fn hmac_account(&self, account: AccountId) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC 接受任意长度密钥");
        mac.update(account.as_bytes());
        let digest = mac.finalize().into_bytes();
        to_hex(&digest[..16])
    }

    /// Wake-up channel name for an account.
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

    /// Enqueue one ciphertext; returns the Stream entry ID used by the client for D-ack.
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

    /// D-ack: atomically delete the queue entry and its image sibling key.
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

    /// Read all un-D-acked entries for this recipient (entry ID + envelope bytes).
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

    /// Wake the gateway holding this account's connection; `payload` is a Stream entry ID or `"k"` (replace the old session).
    pub async fn publish(&self, account: AccountId, payload: &str) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: i64 = redis::cmd("PUBLISH")
            .arg(self.channel(account))
            .arg(payload)
            .query_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Subscribe to the wake-up channel of an account.
    pub async fn subscribe(&self, account: AccountId) -> Result<PubSub, ValkeyError> {
        let mut pubsub = self.client.get_async_pubsub().await?;
        pubsub.subscribe(self.channel(account)).await?;
        Ok(pubsub)
    }

    /// Upload one-time prekeys (Hash, 7-day TTL); returns the total kept server-side.
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

    /// Take one one-time prekey (deleted on take).
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

    /// Store a login challenge: `nonce -> h(account)`, expiring in 60s.
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

    /// Read and delete the challenge in one shot.
    pub async fn take_challenge(&self, nonce: &[u8; 32]) -> Result<Option<String>, ValkeyError> {
        let mut connection = self.connection.clone();
        let value: Option<String> = redis::cmd("GETDEL")
            .arg(challenge_key(nonce))
            .query_async(&mut connection)
            .await?;
        Ok(value)
    }

    /// Take over presence at login; returns the previous instance ID (used to kick the old gateway's connection).
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

    /// Heartbeat refresh: only refresh while presence still belongs to this instance (otherwise a newer login replaced us).
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

    /// Clear presence on disconnect, only while it still belongs to this instance.
    pub async fn clear_presence(&self, account: AccountId) -> Result<(), ValkeyError> {
        let mut connection = self.connection.clone();
        let _: i64 = redis::Script::new(PRESENCE_CLEAR_SCRIPT)
            .key(self.presence_key(account))
            .arg(self.instance_id.as_ref())
            .invoke_async(&mut connection)
            .await?;
        Ok(())
    }

    /// Fixed-window rate limit: returns `true` while the window count stays within `limit`.
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

    /// Aggregate value for `/stats`: total key count (a number only, no content).
    pub async fn dbsize(&self) -> Result<u64, ValkeyError> {
        let mut connection = self.connection.clone();
        let size: i64 = redis::cmd("DBSIZE").query_async(&mut connection).await?;
        Ok(size.max(0) as u64)
    }
}

/// Generate a gateway instance ID (used for presence and replacement checks).
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

/// Raw XRANGE reply -> (entry ID, envelope bytes).
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
