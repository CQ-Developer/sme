//! Gateway runtime state: this instance's live connections, accounts seen and aggregate counters.
//!
//! Queues, prekeys, challenges, presence and rate limits live in Valkey (see [`crate::valkey`]),
//! The gateway itself stores no ciphertext.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sme_proto::{AccountId, Frame};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;

use crate::valkey::Valkey;

/// Cap on concurrently handled big messages (>64KB) so a few 1MB messages cannot exhaust gateway memory (docs/INFRA.md §4.3).
pub const MAX_CONCURRENT_BIG_MESSAGES: usize = 8;

/// Envelopes larger than this go through the big-message semaphore.
pub const BIG_MESSAGE_BYTES: usize = 64 * 1024;

/// Per-account messages-per-minute cap (docs/INFRA.md §4.3).
pub const MESSAGE_RATE_LIMIT_PER_MINUTE: u64 = 120;

/// Per-account login challenges per minute cap.
pub const CHALLENGE_RATE_LIMIT_PER_MINUTE: u64 = 30;

/// A connection handle.
#[derive(Clone)]
pub struct Connection {
    /// Connection sequence number: avoids removing a newer connection when replaced (D10).
    pub conn_id: u64,
    /// Outbound frame channel.
    pub tx: Sender<Frame>,
    /// Ask the read loop to exit (local or remote replacement).
    pub kick: Sender<()>,
}

/// Shared state; `AppState` is cheap to clone.
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

    /// This instance has seen the account (registered or logged in), used to reject deliveries to random IDs.
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
