//! Client core state machine: Olm handshake, encryption/decryption, in-memory buffer and persist signals.
//!
//! Its only inputs and outputs are [`sme_proto::Frame`] and [`Action`]:
//! - `Action::Send` is handed to `sme-client-net` for sending;
//! - On `Action::Persist` the caller writes `account()` / `sessions()` into the keystore;
//! - The rest are events for the UI.

use std::collections::{BTreeMap, BTreeSet};

use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, KdfParams, MessageBody, OlmMessageKind,
    PROTOCOL_VERSION, PreKeyUpload, Registration, Signature, login_payload,
};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, Message as OlmNormalMessage, OlmMessage, PreKeyMessage, Session, SessionConfig,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::MessageBuffer;

/// A decrypted message that entered the in-memory buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub from: AccountId,
    pub body: MessageBody,
}

impl ReceivedMessage {
    pub fn body(&self) -> &MessageBody {
        &self.body
    }

    /// Text contents, when this message is text.
    pub fn text(&self) -> Option<&str> {
        match &self.body {
            MessageBody::Text { text } => Some(text),
            MessageBody::Image { .. } => None,
        }
    }
}

impl Drop for ReceivedMessage {
    fn drop(&mut self) {
        match &mut self.body {
            MessageBody::Text { text } => text.zeroize(),
            MessageBody::Image { bytes, .. } => bytes.zeroize(),
        }
    }
}

impl ZeroizeOnDrop for ReceivedMessage {}

/// Long-term identity keys pinned on first contact (TOFU, D6/I10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPin {
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
}

impl PeerPin {
    /// Flat keystore representation: Ed25519 || Curve25519.
    pub fn to_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.ed25519_pub);
        bytes[32..].copy_from_slice(&self.curve25519_pub);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 64] = bytes.try_into().ok()?;
        Some(Self {
            ed25519_pub: bytes[..32].try_into().ok()?,
            curve25519_pub: bytes[32..].try_into().ok()?,
        })
    }
}

/// An action for the caller to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send immediately through `sme-client-net`.
    Send(Frame),
    /// Newly decrypted message (already in the in-memory buffer).
    Received {
        msg_id: String,
        from: AccountId,
        body: MessageBody,
        /// Images evicted from the buffer to satisfy [`crate::ATTACHMENT_BYTES_LIMIT`].
        dropped_images: usize,
    },
    /// Decryption failed (e.g. duplicate delivery); D-acked but not shown.
    DecryptFailed {
        msg_id: String,
        from: AccountId,
    },
    /// A frame we cannot receive or understand; recorded only, without affecting the connection.
    ProtocolError {
        detail: &'static str,
    },
    /// First contact: the peer's identity keys were pinned; the caller must persist.
    PeerPinned {
        peer: AccountId,
        pin: PeerPin,
    },
    /// A peer presented identity keys that differ from the stored pin. The pin was **not**
    /// changed; sending to this peer is blocked until the user re-verifies it.
    PeerKeyChanged {
        peer: AccountId,
        pinned: PeerPin,
        /// `None` when only the Curve25519 half was observed (inbound pre-key message).
        observed: Option<PeerPin>,
    },
    /// The peer's keys match the stored pin again (for example after a transient server error).
    PeerKeyConfirmed {
        peer: AccountId,
    },
    Registered,
    /// One-time prekeys were uploaded (`stored` is the total kept server-side).
    PreKeysUploaded {
        stored: u16,
    },
    /// The Olm session with the peer is established.
    SessionEstablished {
        peer: AccountId,
    },
    /// A message has been taken over by the server (Q-ack).
    Sent {
        msg_id: String,
    },
    Ready,
    /// Account or session state changed; the caller should persist to the keystore.
    Persist,
    ServerError {
        code: ErrorCode,
        detail: String,
    },
}

#[derive(Debug)]
pub enum CoreError {
    NoSession(AccountId),
    BadEnvelope(&'static str),
    BadBody,
    SessionCreation(vodozemac::olm::SessionCreationError),
    Encryption(vodozemac::olm::EncryptionError),
    Decryption(vodozemac::olm::DecryptionError),
    PeerKeyChanged(AccountId),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession(account) => write!(f, "no established olm session with {account}"),
            Self::BadEnvelope(reason) => write!(f, "bad envelope: {reason}"),
            Self::BadBody => write!(f, "message body is invalid or too large"),
            Self::SessionCreation(error) => write!(f, "olm session creation failed: {error}"),
            Self::Encryption(error) => write!(f, "olm encryption failed: {error}"),
            Self::Decryption(error) => write!(f, "olm decryption failed: {error}"),
            Self::PeerKeyChanged(peer) => write!(
                f,
                "identity of {peer} changed; verify the safety code before sending"
            ),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionCreation(error) => Some(error),
            Self::Encryption(error) => Some(error),
            Self::Decryption(error) => Some(error),
            _ => None,
        }
    }
}

/// Client core: identity, Olm sessions and the plaintext buffer.
pub struct Client {
    account_id: AccountId,
    account: Account,
    sessions: BTreeMap<AccountId, Session>,
    buffer: MessageBuffer<ReceivedMessage>,
    /// TOFU pins, loaded from the keystore and never overwritten automatically.
    pins: BTreeMap<AccountId, PeerPin>,
    /// Peers whose identity changed; sends are refused until the pin is re-verified.
    blocked: BTreeSet<AccountId>,
    /// In-flight identity directory lookups, to avoid one request per queued message.
    requested_identities: BTreeSet<AccountId>,
}

impl Client {
    pub fn new(account_id: AccountId, account: Account) -> Self {
        Self {
            account_id,
            account,
            sessions: BTreeMap::new(),
            buffer: MessageBuffer::new(),
            pins: BTreeMap::new(),
            blocked: BTreeSet::new(),
            requested_identities: BTreeSet::new(),
        }
    }

    /// First registration: generate a random identity (D14).
    pub fn generate(account_id: AccountId) -> Self {
        Self::new(account_id, Account::new())
    }

    /// Restore identity, sessions and TOFU pins from the keystore (the M1 persistence format).
    pub fn restore(
        account_id: AccountId,
        account: Account,
        sessions: impl IntoIterator<Item = (AccountId, Session)>,
        pins: impl IntoIterator<Item = (AccountId, PeerPin)>,
    ) -> Self {
        Self {
            account_id,
            account,
            sessions: sessions.into_iter().collect(),
            buffer: MessageBuffer::new(),
            pins: pins.into_iter().collect(),
            blocked: BTreeSet::new(),
            requested_identities: BTreeSet::new(),
        }
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// Established sessions with their peers, for the caller to persist.
    pub fn sessions(&self) -> impl Iterator<Item = (AccountId, &Session)> {
        self.sessions.iter().map(|(peer, session)| (*peer, session))
    }

    /// TOFU pins, for the caller to persist.
    pub fn peer_pins(&self) -> impl Iterator<Item = (AccountId, &PeerPin)> {
        self.pins.iter().map(|(peer, pin)| (*peer, pin))
    }

    pub fn peer_pin(&self, peer: AccountId) -> Option<&PeerPin> {
        self.pins.get(&peer)
    }

    /// True after [`Action::PeerKeyChanged`] until the pin matches again or the client is restarted.
    pub fn is_peer_blocked(&self, peer: AccountId) -> bool {
        self.blocked.contains(&peer)
    }

    pub fn buffer(&self) -> &MessageBuffer<ReceivedMessage> {
        &self.buffer
    }

    pub fn registration(&self, kdf_salt: [u8; 16], kdf_params: KdfParams) -> Vec<Action> {
        let identity = self.account.identity_keys();
        vec![Action::Send(Frame::Register(Registration {
            account_id: self.account_id,
            ed25519_pub: *identity.ed25519.as_bytes(),
            curve25519_pub: *identity.curve25519.as_bytes(),
            kdf_salt,
            kdf_params,
        }))]
    }

    pub fn challenge_request(&self) -> Vec<Action> {
        vec![Action::Send(Frame::ChallengeRequest {
            account_id: self.account_id,
        })]
    }

    /// Generate a batch of one-time prekeys and mark them published; the caller uploads them.
    pub fn prekey_upload(&mut self, count: usize) -> Vec<Action> {
        self.account.generate_one_time_keys(count);
        let prekeys = self
            .account
            .one_time_keys()
            .into_iter()
            .map(|(key_id, key)| PreKeyUpload {
                key_id: key_id.to_base64(),
                public_key: *key.as_bytes(),
            })
            .collect();
        self.account.mark_keys_as_published();

        vec![
            Action::Send(Frame::UploadPreKeys { prekeys }),
            Action::Persist,
        ]
    }

    pub fn fetch_prekey(&self, peer: AccountId) -> Vec<Action> {
        vec![Action::Send(Frame::FetchPreKey { account_id: peer })]
    }

    /// Encrypt a text/byte message with the existing session.
    /// Encrypt a text message with the existing session.
    pub fn send_text(&mut self, peer: AccountId, text: &str) -> Result<Vec<Action>, CoreError> {
        let body = MessageBody::text(text).map_err(|_| CoreError::BadBody)?;
        self.send_body(peer, &body)
    }

    /// Encrypt a message body (text or image) with the existing session.
    pub fn send_body(
        &mut self,
        peer: AccountId,
        body: &MessageBody,
    ) -> Result<Vec<Action>, CoreError> {
        if self.blocked.contains(&peer) {
            return Err(CoreError::PeerKeyChanged(peer));
        }
        let plaintext = body.encode().map_err(|_| CoreError::BadBody)?;
        let session = self
            .sessions
            .get_mut(&peer)
            .ok_or(CoreError::NoSession(peer))?;
        let message = session.encrypt(&plaintext).map_err(CoreError::Encryption)?;

        let (kind, payload) = match message {
            OlmMessage::PreKey(message) => (OlmMessageKind::PreKey, message.to_bytes()),
            OlmMessage::Normal(message) => (OlmMessageKind::Normal, message.to_bytes()),
        };
        let envelope = Envelope {
            v: PROTOCOL_VERSION,
            from: self.account_id,
            to: peer,
            sid: session.session_id(),
            kind,
            payload,
        };

        Ok(vec![Action::Send(Frame::Send(envelope)), Action::Persist])
    }

    /// Emergency wipe: clear the plaintext buffer and sessions (vodozemac key types wipe themselves on drop).
    pub fn wipe(&mut self) {
        self.buffer.clear();
        self.sessions.clear();
    }

    /// Handle one server frame; returns the actions the caller must perform.
    pub fn handle_frame(&mut self, frame: Frame) -> Vec<Action> {
        match frame {
            Frame::RegisterAck { .. } => vec![Action::Registered],

            Frame::Challenge { nonce } => {
                let signature = self.account.sign(login_payload(&self.account_id, &nonce));
                vec![Action::Send(Frame::Login {
                    account_id: self.account_id,
                    nonce,
                    signature: Signature::from_bytes(signature.to_bytes()),
                })]
            }

            Frame::LoginAck { .. } => vec![Action::Ready],

            Frame::UploadPreKeysAck { stored } => vec![Action::PreKeysUploaded { stored }],

            Frame::SendAck { msg_id } => vec![Action::Sent { msg_id }],

            Frame::PreKeyBundle(bundle) => {
                let peer = bundle.account_id;
                let observed = PeerPin {
                    ed25519_pub: bundle.ed25519_pub,
                    curve25519_pub: bundle.curve25519_pub,
                };
                let mut actions = self.observe_identity(peer, observed);
                if actions
                    .iter()
                    .any(|action| matches!(action, Action::PeerKeyChanged { .. }))
                {
                    return actions;
                }
                self.requested_identities.remove(&peer);

                match self.account.create_outbound_session(
                    SessionConfig::default(),
                    Curve25519PublicKey::from_bytes(bundle.curve25519_pub),
                    Curve25519PublicKey::from_bytes(bundle.one_time_key),
                ) {
                    Ok(session) => {
                        self.sessions.insert(peer, session);
                        actions.push(Action::SessionEstablished { peer });
                        if !actions
                            .iter()
                            .any(|action| matches!(action, Action::Persist))
                        {
                            actions.push(Action::Persist);
                        }
                        actions
                    }
                    Err(_) => {
                        actions.push(Action::ProtocolError {
                            detail: "failed to create outbound session",
                        });
                        actions
                    }
                }
            }

            Frame::IdentityKeys {
                account_id,
                ed25519_pub,
                curve25519_pub,
            } => {
                self.requested_identities.remove(&account_id);
                self.observe_identity(
                    account_id,
                    PeerPin {
                        ed25519_pub,
                        curve25519_pub,
                    },
                )
            }

            Frame::Deliver { msg_id, envelope } => self.handle_deliver(msg_id, envelope),

            Frame::Error { code, detail } => {
                // A failed lookup should not suppress retries for every peer.
                self.requested_identities.clear();
                vec![Action::ServerError { code, detail }]
            }

            _ => vec![],
        }
    }

    /// Compare observed keys with the stored pin; never overwrite a pin on a mismatch.
    fn observe_identity(&mut self, peer: AccountId, observed: PeerPin) -> Vec<Action> {
        match self.pins.get(&peer).copied() {
            None => {
                self.pins.insert(peer, observed);
                self.blocked.remove(&peer);
                vec![
                    Action::PeerPinned {
                        peer,
                        pin: observed,
                    },
                    Action::Persist,
                ]
            }
            Some(pinned) if pinned != observed => {
                self.blocked.insert(peer);
                vec![Action::PeerKeyChanged {
                    peer,
                    pinned,
                    observed: Some(observed),
                }]
            }
            Some(_) => {
                if self.blocked.remove(&peer) {
                    vec![Action::PeerKeyConfirmed { peer }]
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Detect an identity change in an inbound pre-key message and request the peer's
    /// directory entry on first contact (the pre-key message carries Curve25519 only).
    fn observe_inbound_identity(&mut self, from: AccountId, envelope: &Envelope) -> Vec<Action> {
        if envelope.kind != OlmMessageKind::PreKey {
            return Vec::new();
        }
        let Ok(pre_key) = PreKeyMessage::from_bytes(&envelope.payload) else {
            return Vec::new();
        };
        let observed_curve25519 = *pre_key.identity_key().as_bytes();

        if let Some(pinned) = self.pins.get(&from).copied()
            && pinned.curve25519_pub != observed_curve25519
        {
            self.blocked.insert(from);
            return vec![Action::PeerKeyChanged {
                peer: from,
                pinned,
                observed: None,
            }];
        }

        if self.requested_identities.insert(from) {
            vec![Action::Send(Frame::FetchIdentity { account_id: from })]
        } else {
            Vec::new()
        }
    }

    fn handle_deliver(&mut self, msg_id: String, envelope: Envelope) -> Vec<Action> {
        let from = envelope.from;
        let mut identity_actions = self.observe_inbound_identity(from, &envelope);
        if identity_actions
            .iter()
            .any(|action| matches!(action, Action::PeerKeyChanged { .. }))
        {
            // Do not display a message whose pre-key identity does not match the pin.
            identity_actions.push(Action::Send(Frame::DeliverAck { msg_id }));
            return identity_actions;
        }

        match self.decrypt(&envelope) {
            Ok((body, session_changed)) => {
                let dropped_images = self.buffer.push_received(ReceivedMessage {
                    from,
                    body: body.clone(),
                });

                let mut actions = identity_actions;
                actions.push(Action::Received {
                    msg_id: msg_id.clone(),
                    from,
                    body,
                    dropped_images,
                });
                actions.push(Action::Send(Frame::DeliverAck { msg_id }));
                if session_changed {
                    actions.push(Action::Persist);
                }
                actions
            }
            Err(_) => {
                let mut actions = identity_actions;
                actions.push(Action::DecryptFailed {
                    msg_id: msg_id.clone(),
                    from,
                });
                // Duplicate delivery consumed the message key: still D-ack, or the server keeps redelivering
                actions.push(Action::Send(Frame::DeliverAck { msg_id }));
                actions
            }
        }
    }

    /// Decrypt one envelope; returns `(body, local state changed)`.
    fn decrypt(&mut self, envelope: &Envelope) -> Result<(MessageBody, bool), CoreError> {
        let (plaintext, session_changed) = self.decrypt_plaintext(envelope)?;
        let body = MessageBody::decode(&plaintext).map_err(|_| CoreError::BadBody)?;
        Ok((body, session_changed))
    }

    /// Decrypt one envelope to raw plaintext bytes; returns `(plaintext, local state changed)`.
    fn decrypt_plaintext(
        &mut self,
        envelope: &Envelope,
    ) -> Result<(Zeroizing<Vec<u8>>, bool), CoreError> {
        if envelope.to != self.account_id {
            return Err(CoreError::BadEnvelope(
                "envelope addressed to another account",
            ));
        }
        let from = envelope.from;

        match envelope.kind {
            OlmMessageKind::PreKey => {
                // Duplicate or out-of-order delivery: try the existing session first.
                if let Some(session) = self.sessions.get_mut(&from)
                    && let Ok(message) = PreKeyMessage::from_bytes(&envelope.payload)
                    && let Ok(plaintext) = session.decrypt(&OlmMessage::PreKey(message))
                {
                    return Ok((Zeroizing::new(plaintext), true));
                }

                let pre_key = PreKeyMessage::from_bytes(&envelope.payload)
                    .map_err(|_| CoreError::BadEnvelope("bad pre-key message"))?;
                let identity_key = pre_key.identity_key();
                let inbound = self
                    .account
                    .create_inbound_session(SessionConfig::default(), identity_key, &pre_key)
                    .map_err(CoreError::SessionCreation)?;
                self.sessions.insert(from, inbound.session);
                Ok((Zeroizing::new(inbound.plaintext), true))
            }

            OlmMessageKind::Normal => {
                let message = OlmNormalMessage::from_bytes(&envelope.payload)
                    .map_err(|_| CoreError::BadEnvelope("bad normal message"))?;
                let session = self
                    .sessions
                    .get_mut(&from)
                    .ok_or(CoreError::NoSession(from))?;
                let plaintext = session
                    .decrypt(&OlmMessage::Normal(message))
                    .map_err(CoreError::Decryption)?;
                Ok((Zeroizing::new(plaintext), true))
            }
        }
    }
}
