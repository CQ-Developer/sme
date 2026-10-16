//! 网关运行时状态：本实例的活连接、已见账号与聚合计数。
//!
//! 队列、预密钥、挑战、presence、限流都在 Valkey（见 [`crate::valkey`]），
//! 网关本身不保存任何密文。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sme_proto::{AccountId, Frame};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;

use crate::valkey::Valkey;

/// 同时处理的大消息（>64KB）上限，防止少量 1MB 消息吃光网关内存（docs/INFRA.md §4.3）。
pub const MAX_CONCURRENT_BIG_MESSAGES: usize = 8;

/// 超过该大小的信封走大消息信号量。
pub const BIG_MESSAGE_BYTES: usize = 64 * 1024;

/// 每账号每分钟消息上限（docs/INFRA.md §4.3）。
pub const MESSAGE_RATE_LIMIT_PER_MINUTE: u64 = 120;

/// 每账号每分钟登录挑战上限。
pub const CHALLENGE_RATE_LIMIT_PER_MINUTE: u64 = 30;

/// 一条连接句柄。
#[derive(Clone)]
pub struct Connection {
    /// 连接序号：被顶替（D10）时用来避免误删新连接。
    pub conn_id: u64,
    /// 出站帧通道。
    pub tx: Sender<Frame>,
    /// 让读循环主动退出（顶替 / 远端踢出）。
    pub kick: Sender<()>,
}

/// 共享状态；`AppState` 可以随意 clone。
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub valkey: Valkey,
    next_conn_id: Arc<AtomicU64>,
    connections: Arc<Mutex<HashMap<AccountId, Connection>>>,
    known: Arc<Mutex<HashSet<AccountId>>>,
    forwarded: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    big_messages: Arc<Semaphore>,
}

impl AppState {
    pub fn new(db: PgPool, valkey: Valkey) -> Self {
        Self {
            db,
            valkey,
            next_conn_id: Arc::new(AtomicU64::new(1)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            known: Arc::new(Mutex::new(HashSet::new())),
            forwarded: Arc::new(AtomicU64::new(0)),
            rejected: Arc::new(AtomicU64::new(0)),
            big_messages: Arc::new(Semaphore::new(MAX_CONCURRENT_BIG_MESSAGES)),
        }
    }

    pub fn next_connection_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn connections(&self) -> MutexGuard<'_, HashMap<AccountId, Connection>> {
        self.connections.lock().expect("connections mutex poisoned")
    }

    pub fn is_current_connection(&self, account: AccountId, conn_id: u64) -> bool {
        self.connections()
            .get(&account)
            .is_some_and(|connection| connection.conn_id == conn_id)
    }

    pub fn remove_connection(&self, account: AccountId, conn_id: u64) {
        let mut connections = self.connections();
        if connections
            .get(&account)
            .is_some_and(|connection| connection.conn_id == conn_id)
        {
            connections.remove(&account);
        }
    }

    pub fn known(&self) -> MutexGuard<'_, HashSet<AccountId>> {
        self.known.lock().expect("known mutex poisoned")
    }

    /// 这个实例见过该账号（注册或成功登录过），用于拒绝随机 ID 的投递。
    pub fn is_known(&self, account_id: AccountId) -> bool {
        self.known().contains(&account_id)
    }

    pub fn mark_known(&self, account_id: AccountId) {
        self.known().insert(account_id);
    }

    pub fn count_forwarded(&self) {
        self.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_count(&self) -> usize {
        self.connections().len()
    }

    pub fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    pub fn big_messages(&self) -> &Semaphore {
        &self.big_messages
    }
}
