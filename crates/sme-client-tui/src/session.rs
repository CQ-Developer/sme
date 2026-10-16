//! 无 UI 的客户端会话：连接、注册/登录、收发、持久化与擦除。
//!
//! 这是 TUI（以及将来桌面/移动外壳）共用的运行时：它把
//! `sme-client-net`（传输）、`sme-client-core`（Olm 状态机）与
//! `sme-client-store`（keystore）拼起来，向 UI 暴露 [`Event`] 与几个操作。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use sme_client_core::{Action, Client, CoreError, MessageBuffer, ReceivedMessage};
use sme_client_net::{NetError, Transport};
use sme_client_store::{Keystore, LocalConfig, StoreError};
use sme_proto::{AccountId, ErrorCode};

/// 每次上传的一次性预密钥数量。
pub const PREKEY_BATCH: usize = 5;

#[derive(Debug)]
pub enum SessionError {
    Io(std::io::Error),
    Store(StoreError),
    Net(NetError),
    Core(CoreError),
    Disconnected,
    MissingAccount,
    Server { code: ErrorCode, detail: String },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Store(error) => write!(f, "keystore error: {error}"),
            Self::Net(error) => write!(f, "network error: {error}"),
            Self::Core(error) => write!(f, "core error: {error}"),
            Self::Disconnected => write!(f, "server closed the connection"),
            Self::MissingAccount => write!(f, "keystore has no account"),
            Self::Server { code, detail } => write!(f, "server error {code:?}: {detail}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Net(error) => Some(error),
            Self::Core(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SessionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StoreError> for SessionError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<NetError> for SessionError {
    fn from(error: NetError) -> Self {
        Self::Net(error)
    }
}

/// 给 UI 的事件；`text` 是 UI 边界的字符串副本（无法完全擦除，见 plan.md §11）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Registered,
    Ready,
    PreKeysUploaded { stored: u16 },
    SessionEstablished { peer: AccountId },
    Sent { msg_id: String },
    Received { from: AccountId, text: String },
    DecryptFailed { from: AccountId },
    ServerError { code: ErrorCode, detail: String },
    ProtocolError { detail: &'static str },
}

/// 一条登录好的客户端会话。
pub struct Session {
    client: Client,
    keystore: Keystore,
    keystore_path: PathBuf,
    config: LocalConfig,
    transport: Transport,
    events: VecDeque<Event>,
}

impl Session {
    /// 打开（或创建）keystore、连接服务器、注册（幂等）并登录。
    pub async fn connect(
        url: &str,
        keystore_path: &Path,
        password: &[u8],
    ) -> Result<Self, SessionError> {
        let (config, client, keystore) = match LocalConfig::load(keystore_path)? {
            Some(config) => {
                let keystore = Keystore::open(keystore_path, password)?;
                let account = keystore
                    .load_account()?
                    .ok_or(SessionError::MissingAccount)?;
                let sessions = keystore.load_sessions()?;
                let client = Client::restore(config.account_id, account, sessions);
                (config, client, keystore)
            }
            None => {
                let keystore = Keystore::create(keystore_path, password)?;
                let config = LocalConfig::new_random()?;
                config.save(keystore_path)?;
                let client = Client::generate(config.account_id);
                (config.clone(), client, keystore)
            }
        };

        let transport = Transport::connect(url).await?;

        let mut session = Self {
            client,
            keystore,
            keystore_path: keystore_path.to_path_buf(),
            config,
            transport,
            events: VecDeque::new(),
        };
        session.persist()?;

        // 注册是幂等的：已注册时服务端回 AlreadyRegistered，同样继续登录。
        let actions = session
            .client
            .registration(session.config.kdf_salt, session.config.kdf_params);
        session.run_actions(actions).await?;
        loop {
            match session.next_event().await? {
                Event::Registered => break,
                Event::ServerError {
                    code: ErrorCode::AlreadyRegistered,
                    ..
                } => break,
                Event::ServerError { code, detail } => {
                    return Err(SessionError::Server { code, detail });
                }
                _ => {}
            }
        }

        let actions = session.client.challenge_request();
        session.run_actions(actions).await?;
        loop {
            match session.next_event().await? {
                Event::Ready => break,
                Event::ServerError { code, detail } => {
                    return Err(SessionError::Server { code, detail });
                }
                _ => {}
            }
        }

        Ok(session)
    }

    pub fn account_id(&self) -> AccountId {
        self.config.account_id
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// 内存中的明文缓冲（≤10 条，永不落盘）。
    pub fn messages(&self) -> &MessageBuffer<ReceivedMessage> {
        self.client.buffer()
    }

    /// 处理网络帧直到产出下一个 UI 事件。
    pub async fn next_event(&mut self) -> Result<Event, SessionError> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            let frame = self
                .transport
                .recv()
                .await?
                .ok_or(SessionError::Disconnected)?;
            let actions = self.client.handle_frame(frame);
            let events = self.run_actions(actions).await?;
            self.events.extend(events);
        }
    }

    pub async fn send_text(&mut self, peer: AccountId, text: &[u8]) -> Result<(), SessionError> {
        let actions = self
            .client
            .send_text(peer, text)
            .map_err(SessionError::Core)?;
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    pub async fn fetch_prekey(&mut self, peer: AccountId) -> Result<(), SessionError> {
        let actions = self.client.fetch_prekey(peer);
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    pub async fn upload_prekeys(&mut self, count: usize) -> Result<(), SessionError> {
        let actions = self.client.prekey_upload(count);
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    /// 紧急擦除内存：明文缓冲、会话与待处理事件。
    pub fn wipe_memory(&mut self) {
        self.client.wipe();
        self.events.clear();
    }

    /// 危险操作：删除 keystore 与本地配置（紧急擦除快捷键用）。
    pub fn delete_keystore(&self) -> Result<(), SessionError> {
        for path in [
            self.keystore_path.clone(),
            LocalConfig::path_for(&self.keystore_path),
        ] {
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    async fn run_actions(&mut self, actions: Vec<Action>) -> Result<Vec<Event>, SessionError> {
        let mut events = Vec::new();
        for action in actions {
            match action {
                Action::Send(frame) => self.transport.send(&frame).await?,
                Action::Persist => self.persist()?,
                other => events.push(to_event(other)),
            }
        }
        Ok(events)
    }

    fn persist(&mut self) -> Result<(), SessionError> {
        self.keystore.save_account(self.client.account())?;
        for (peer, session) in self.client.sessions() {
            self.keystore.save_session(peer, session)?;
        }
        self.keystore.save()?;
        Ok(())
    }
}

fn to_event(action: Action) -> Event {
    match action {
        Action::Registered => Event::Registered,
        Action::Ready => Event::Ready,
        Action::PreKeysUploaded { stored } => Event::PreKeysUploaded { stored },
        Action::SessionEstablished { peer } => Event::SessionEstablished { peer },
        Action::Sent { msg_id } => Event::Sent { msg_id },
        Action::Received {
            from, plaintext, ..
        } => Event::Received {
            from,
            text: String::from_utf8_lossy(&plaintext).into_owned(),
        },
        Action::DecryptFailed { from, .. } => Event::DecryptFailed { from },
        Action::ServerError { code, detail } => Event::ServerError { code, detail },
        Action::ProtocolError { detail } => Event::ProtocolError { detail },
        Action::Send(_) | Action::Persist => {
            unreachable!("Send/Persist 已在 run_actions 中处理")
        }
    }
}
