//! 网关运行时状态：活连接、登录挑战、一次性预密钥与离线密文队列。
//!
//! M2 全部在进程内存中（单实例）；M3 迁移到 Valkey + 无状态网关，这些语义不变。

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use sme_proto::{AccountId, Envelope, Frame, PreKeyUpload};
use sqlx::PgPool;
use tokio::sync::mpsc::Sender;

/// 每个收件人最多暂存的密文条数（与 D7 一致）。
pub const MAX_QUEUED_PER_RECIPIENT: usize = 100;

/// 未消费登录挑战的上限，防止无界增长。
pub const MAX_PENDING_CHALLENGES: usize = 10_000;

/// 每个账号在服务端保存的一次性预密钥上限。
pub const MAX_STORED_PREKEYS: usize = 100;

/// 一条连接句柄。
#[derive(Clone)]
pub struct Connection {
    /// 连接序号：登录被顶替（D10）时用来避免误删新连接。
    pub conn_id: u64,
    pub tx: Sender<Frame>,
}

/// 一次性登录挑战。
pub struct Challenge {
    pub nonce: [u8; 32],
    pub issued_at: Instant,
}

/// 队列里尚未 D-ack 的密文。
#[derive(Clone)]
pub struct QueuedMessage {
    pub msg_id: u64,
    pub envelope: Envelope,
}

/// 共享状态；`AppState` 可以随意 clone。
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    next_conn_id: Arc<AtomicU64>,
    next_msg_id: Arc<AtomicU64>,
    connections: Arc<Mutex<HashMap<AccountId, Connection>>>,
    challenges: Arc<Mutex<HashMap<AccountId, Challenge>>>,
    prekeys: Arc<Mutex<HashMap<AccountId, VecDeque<PreKeyUpload>>>>,
    queues: Arc<Mutex<HashMap<AccountId, VecDeque<QueuedMessage>>>>,
    known: Arc<Mutex<HashSet<AccountId>>>,
}

impl AppState {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            next_conn_id: Arc::new(AtomicU64::new(1)),
            next_msg_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            prekeys: Arc::new(Mutex::new(HashMap::new())),
            queues: Arc::new(Mutex::new(HashMap::new())),
            known: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn next_connection_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_message_id(&self) -> u64 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn connections(&self) -> MutexGuard<'_, HashMap<AccountId, Connection>> {
        self.connections.lock().expect("connections mutex poisoned")
    }

    pub fn challenges(&self) -> MutexGuard<'_, HashMap<AccountId, Challenge>> {
        self.challenges.lock().expect("challenges mutex poisoned")
    }

    pub fn prekeys(&self) -> MutexGuard<'_, HashMap<AccountId, VecDeque<PreKeyUpload>>> {
        self.prekeys.lock().expect("prekeys mutex poisoned")
    }

    pub fn queues(&self) -> MutexGuard<'_, HashMap<AccountId, VecDeque<QueuedMessage>>> {
        self.queues.lock().expect("queues mutex poisoned")
    }

    pub fn known(&self) -> MutexGuard<'_, HashSet<AccountId>> {
        self.known.lock().expect("known mutex poisoned")
    }

    /// 这个实例见过该账号（注册或成功登录过）。
    pub fn is_known(&self, account_id: AccountId) -> bool {
        self.known().contains(&account_id)
    }
}
