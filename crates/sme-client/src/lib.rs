//! Headless client runtime shared by the TUI and the mobile shells: it wires
//! `sme-client-net` (transport), `sme-client-core` (Olm state machine) and
//! `sme-client-store` (keystore) into one session with a small event API.
//!
//! Runtime shared by the TUI (and future desktop/mobile shells): it wires
//! `sme-client-net` (transport), `sme-client-core` (Olm state machine) and
//! `sme-client-store` (keystore) into one runtime that exposes [`Event`] and a few operations to the UI.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use sme_client_core::{Action, Client, MessageBuffer, ReceivedMessage};
use sme_client_net::{NetError, Transport};
use sme_client_store::{Keystore, LocalConfig, StoreError};
use sme_proto::{AccountId, ErrorCode, MessageBody};

pub use sme_client_core::{ATTACHMENT_BYTES_LIMIT, CoreError, MESSAGE_BUFFER_LIMIT, PeerPin};

/// Number of one-time prekeys per upload.
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

/// What kind of message arrived; the full body stays in the core buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedKind {
    Text(String),
    Image {
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
}

/// Events for the UI; `text` is a string copy at the UI boundary (not fully wipeable, see plan.md §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Registered,
    Ready,
    PreKeysUploaded {
        stored: u16,
    },
    SessionEstablished {
        peer: AccountId,
    },
    Sent {
        msg_id: String,
    },
    Received {
        from: AccountId,
        kind: ReceivedKind,
        /// Images dropped from the plaintext buffer by the 8 MiB attachment budget.
        dropped_images: usize,
    },
    DecryptFailed {
        from: AccountId,
    },
    ServerError {
        code: ErrorCode,
        detail: String,
    },
    ProtocolError {
        detail: &'static str,
    },
    /// First contact: the peer's identity keys were pinned (TOFU).
    PeerPinned {
        peer: AccountId,
        pin: PeerPin,
    },
    /// The peer presented different identity keys; the stored pin was not changed.
    PeerKeyChanged {
        peer: AccountId,
        pinned: PeerPin,
        /// `None` when only the inbound pre-key Curve25519 key was observed.
        observed: Option<PeerPin>,
    },
    /// The peer's keys match the stored pin again.
    PeerKeyConfirmed {
        peer: AccountId,
    },
    /// A local SAS verification was started; waiting for the peer.
    SasStarted {
        peer: AccountId,
    },
    /// Both sides derived the code; show it and compare it out of band.
    /// `emojis` are Matrix SAS indices (0..=63).
    SasCode {
        peer: AccountId,
        emojis: [u8; 7],
        decimals: (u16, u16, u16),
    },
    /// The peer confirmed the code; the local user still has to confirm.
    SasPeerConfirmed {
        peer: AccountId,
    },
    /// The local user confirmed; waiting for the peer's MAC.
    SasLocalConfirmed {
        peer: AccountId,
    },
    /// Both MACs verified; the pin is now marked as verified.
    SasVerified {
        peer: AccountId,
    },
    SasFailed {
        peer: AccountId,
    },
    SasCancelled {
        peer: AccountId,
    },
}

/// A logged-in client session.
pub struct Session {
    client: Client,
    keystore: Keystore,
    keystore_path: PathBuf,
    config: LocalConfig,
    transport: Transport,
    events: VecDeque<Event>,
}

impl Session {
    /// Open (or create) the keystore, connect to the server, register (idempotently) and log in.
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
                let pins = load_peer_pins(&keystore)?;
                let verified = load_verified_peers(&keystore)?;
                let client = Client::restore(config.account_id, account, sessions, pins, verified);
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

        // Registration is idempotent: an AlreadyRegistered reply still proceeds to login.
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

    /// In-memory plaintext buffer (10 entries max, never written to disk).
    pub fn messages(&self) -> &MessageBuffer<ReceivedMessage> {
        self.client.buffer()
    }

    /// Process network frames until the next UI event is produced.
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

    pub async fn send_text(&mut self, peer: AccountId, text: &str) -> Result<(), SessionError> {
        let actions = self
            .client
            .send_text(peer, text)
            .map_err(SessionError::Core)?;
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    /// Send an arbitrary body (text or prepared image).
    pub async fn send_body(
        &mut self,
        peer: AccountId,
        body: &MessageBody,
    ) -> Result<(), SessionError> {
        let actions = self
            .client
            .send_body(peer, body)
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

    /// TOFU pin for a peer, if first contact has already happened.
    pub fn peer_pin(&self, peer: AccountId) -> Option<PeerPin> {
        self.client.peer_pin(peer).copied()
    }

    /// True when the current pin passed an interactive SAS verification.
    pub fn is_peer_verified(&self, peer: AccountId) -> bool {
        self.client.is_peer_verified(peer)
    }

    pub async fn start_sas(&mut self, peer: AccountId) -> Result<(), SessionError> {
        let actions = self.client.start_sas(peer).map_err(SessionError::Core)?;
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    pub async fn confirm_sas(&mut self, peer: AccountId) -> Result<(), SessionError> {
        let actions = self.client.confirm_sas(peer).map_err(SessionError::Core)?;
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    pub async fn cancel_sas(&mut self, peer: AccountId) -> Result<(), SessionError> {
        let actions = self.client.cancel_sas(peer);
        let events = self.run_actions(actions).await?;
        self.events.extend(events);
        Ok(())
    }

    /// Emergency memory wipe: plaintext buffer, sessions and pending events.
    pub fn wipe_memory(&mut self) {
        self.client.wipe();
        self.events.clear();
    }

    /// Dangerous: delete the keystore and local config (used by the emergency-wipe hotkey).
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
        for (peer, pin) in self.client.peer_pins() {
            self.keystore
                .put(format!("peer.pin.{peer}"), pin.to_bytes().to_vec());
        }
        let verified: Vec<String> = self
            .client
            .verified_peers()
            .map(|peer| peer.to_base32())
            .collect();
        self.keystore
            .put(PEER_VERIFIED_KEY, verified.join("\n").into_bytes());
        self.keystore.save()?;
        Ok(())
    }
}

const PEER_PIN_PREFIX: &str = "peer.pin.";
const PEER_VERIFIED_KEY: &str = "peer.verified";

/// Load TOFU pins from the keystore; a malformed record is an error, not a silent reset.
fn load_peer_pins(keystore: &Keystore) -> Result<BTreeMap<AccountId, PeerPin>, SessionError> {
    let mut pins = BTreeMap::new();
    for (key, value) in keystore.entries_with_prefix(PEER_PIN_PREFIX) {
        let account = key
            .strip_prefix(PEER_PIN_PREFIX)
            .and_then(|id| id.parse::<AccountId>().ok())
            .ok_or(SessionError::Store(StoreError::Corrupt(
                "bad peer pin account id",
            )))?;
        let pin = PeerPin::from_bytes(value).ok_or(SessionError::Store(StoreError::Corrupt(
            "bad peer pin value",
        )))?;
        pins.insert(account, pin);
    }
    Ok(pins)
}

/// Load the set of peers whose pin passed SAS verification.
fn load_verified_peers(keystore: &Keystore) -> Result<BTreeSet<AccountId>, SessionError> {
    let Some(bytes) = keystore.get(PEER_VERIFIED_KEY) else {
        return Ok(BTreeSet::new());
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| SessionError::Store(StoreError::Corrupt("bad verified peer list")))?;
    let mut peers = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let peer = line.parse::<AccountId>().map_err(|_| {
            SessionError::Store(StoreError::Corrupt("bad verified peer account id"))
        })?;
        peers.insert(peer);
    }
    Ok(peers)
}

fn to_event(action: Action) -> Event {
    match action {
        Action::Registered => Event::Registered,
        Action::Ready => Event::Ready,
        Action::PreKeysUploaded { stored } => Event::PreKeysUploaded { stored },
        Action::SessionEstablished { peer } => Event::SessionEstablished { peer },
        Action::Sent { msg_id } => Event::Sent { msg_id },
        Action::Received {
            from,
            body,
            dropped_images,
            ..
        } => Event::Received {
            from,
            dropped_images,
            kind: match body {
                MessageBody::Text { text } => ReceivedKind::Text(text),
                MessageBody::Image {
                    width,
                    height,
                    bytes,
                } => ReceivedKind::Image {
                    width,
                    height,
                    bytes,
                },
                MessageBody::Sas(_) => {
                    unreachable!("SAS frames are handled by the client core")
                }
            },
        },
        Action::DecryptFailed { from, .. } => Event::DecryptFailed { from },
        Action::ServerError { code, detail } => Event::ServerError { code, detail },
        Action::ProtocolError { detail } => Event::ProtocolError { detail },
        Action::PeerPinned { peer, pin } => Event::PeerPinned { peer, pin },
        Action::PeerKeyChanged {
            peer,
            pinned,
            observed,
        } => Event::PeerKeyChanged {
            peer,
            pinned,
            observed,
        },
        Action::PeerKeyConfirmed { peer } => Event::PeerKeyConfirmed { peer },
        Action::SasStarted { peer } => Event::SasStarted { peer },
        Action::SasCode {
            peer,
            emojis,
            decimals,
        } => Event::SasCode {
            peer,
            emojis,
            decimals,
        },
        Action::SasPeerConfirmed { peer } => Event::SasPeerConfirmed { peer },
        Action::SasLocalConfirmed { peer } => Event::SasLocalConfirmed { peer },
        Action::SasVerified { peer } => Event::SasVerified { peer },
        Action::SasFailed { peer } => Event::SasFailed { peer },
        Action::SasCancelled { peer } => Event::SasCancelled { peer },
        Action::Send(_) | Action::Persist => {
            unreachable!("Send/Persist are handled in run_actions")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sme-client-pins-{}-{}-{name}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn peer_pins_roundtrip_through_the_keystore() {
        let dir = scratch("roundtrip");
        let path = dir.join("keystore.bin");
        let password = b"test passphrase";

        let peer = AccountId::random();
        let pin = PeerPin {
            ed25519_pub: [0xAB; 32],
            curve25519_pub: [0xCD; 32],
        };
        {
            let mut keystore = Keystore::create(&path, password).expect("create keystore");
            keystore.put("olm.account", b"unrelated".to_vec());
            keystore.put(format!("peer.pin.{peer}"), pin.to_bytes().to_vec());
            keystore.save().expect("save keystore");
        }

        let keystore = Keystore::open(&path, password).expect("reopen keystore");
        let pins = load_peer_pins(&keystore).expect("load pins");
        assert_eq!(pins.len(), 1);
        assert_eq!(pins.get(&peer), Some(&pin));

        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn verified_peer_list_roundtrips_and_rejects_garbage() {
        let dir = scratch("verified");
        let path = dir.join("keystore.bin");
        let password = b"test passphrase";
        let peer = AccountId::random();

        let mut keystore = Keystore::create(&path, password).expect("create keystore");
        keystore.put(PEER_VERIFIED_KEY, peer.to_base32().into_bytes());
        keystore.save().expect("save keystore");

        let keystore = Keystore::open(&path, password).expect("reopen keystore");
        let verified = load_verified_peers(&keystore).expect("load verified peers");
        assert_eq!(verified.len(), 1);
        assert!(verified.contains(&peer));

        let mut keystore = Keystore::open(&path, password).expect("reopen keystore");
        keystore.put(PEER_VERIFIED_KEY, b"not-an-account".to_vec());
        keystore.save().expect("save keystore");
        let keystore = Keystore::open(&path, password).expect("reopen keystore");
        assert!(matches!(
            load_verified_peers(&keystore),
            Err(SessionError::Store(StoreError::Corrupt(_)))
        ));

        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn malformed_pin_records_are_rejected_instead_of_reset() {
        let dir = scratch("malformed");
        let path = dir.join("keystore.bin");
        let password = b"test passphrase";

        let mut keystore = Keystore::create(&path, password).expect("create keystore");
        keystore.put("peer.pin.not-an-account", vec![0u8; 64]);
        keystore.save().expect("save keystore");

        let keystore = Keystore::open(&path, password).expect("reopen keystore");
        assert!(matches!(
            load_peer_pins(&keystore),
            Err(SessionError::Store(StoreError::Corrupt(_)))
        ));

        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
