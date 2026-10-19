//! Client core state machine: Olm handshake, encryption/decryption, in-memory buffer and persist signals.
//!
//! Its only inputs and outputs are [`sme_proto::Frame`] and [`Action`]:
//! - `Action::Send` is handed to `sme-client-net` for sending;
//! - On `Action::Persist` the caller writes `account()` / `sessions()` into the keystore;
//! - The rest are events for the UI.

use std::collections::{BTreeMap, BTreeSet};

use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, KdfParams, MessageBody, OlmMessageKind,
    PROTOCOL_VERSION, PreKeyUpload, Registration, SasMessage, Signature, login_payload,
};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, Message as OlmNormalMessage, OlmMessage, PreKeyMessage, Session, SessionConfig,
};
use vodozemac::sas::{EstablishedSas, Mac, Sas};
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
            MessageBody::Image { .. } | MessageBody::Sas(_) => None,
        }
    }
}

impl Drop for ReceivedMessage {
    fn drop(&mut self) {
        match &mut self.body {
            MessageBody::Text { text } => text.zeroize(),
            MessageBody::Image { bytes, .. } => bytes.zeroize(),
            MessageBody::Sas(_) => {}
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

/// Domain separator for the emoji/decimal SAS code.
const SAS_INFO: &str = "sme-sas-v1";
/// Domain separator and context for the identity-key MAC exchange.
const SAS_MAC_INFO: &str = "sme-sas-mac-v1";

/// One interactive SAS verification at a time (plan.md D28).
struct SasSession {
    peer: AccountId,
    state: SasState,
}

enum SasState {
    /// We sent `Start` and wait for the peer's public key.
    WaitingForPeer(Sas),
    /// Both sides can compute the code; waiting for local confirmation and/or the peer's MAC.
    AwaitingPeerConfirm {
        established: EstablishedSas,
        peer_confirmed: bool,
    },
    /// Local user confirmed and our MAC was sent; waiting for the peer's MAC.
    AwaitingPeerMac { established: EstablishedSas },
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
    /// A local SAS verification was started; waiting for the peer's ephemeral key.
    SasStarted {
        peer: AccountId,
    },
    /// Both SAS sides derived the code; show it and ask the user to compare it out of band.
    SasCode {
        peer: AccountId,
        emojis: [u8; 7],
        decimals: (u16, u16, u16),
    },
    /// The peer sent a valid MAC and confirmed the code; the local user still has to confirm.
    SasPeerConfirmed {
        peer: AccountId,
    },
    /// The local user confirmed; our MAC was sent and we wait for the peer's MAC.
    SasLocalConfirmed {
        peer: AccountId,
    },
    /// Both MACs verified; the peer's pin is now marked as verified.
    SasVerified {
        peer: AccountId,
    },
    /// A SAS MAC failed or the handshake was invalid; the pin stays unverified.
    SasFailed {
        peer: AccountId,
    },
    SasCancelled {
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
    NoPin(AccountId),
    SasInProgress,
    SasNotReady,
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
            Self::NoPin(peer) => write!(
                f,
                "no pinned identity for {peer}; complete first contact first"
            ),
            Self::SasInProgress => write!(f, "a SAS verification is already in progress"),
            Self::SasNotReady => write!(f, "SAS verification is not ready for this action"),
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
    /// Peers whose current pin passed an interactive SAS verification.
    verified: BTreeSet<AccountId>,
    /// At most one SAS verification is in flight.
    sas: Option<SasSession>,
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
            verified: BTreeSet::new(),
            sas: None,
        }
    }

    /// First registration: generate a random identity (D14).
    pub fn generate(account_id: AccountId) -> Self {
        Self::new(account_id, Account::new())
    }

    /// Restore identity, sessions, TOFU pins and SAS verification state from the keystore.
    pub fn restore(
        account_id: AccountId,
        account: Account,
        sessions: impl IntoIterator<Item = (AccountId, Session)>,
        pins: impl IntoIterator<Item = (AccountId, PeerPin)>,
        verified: impl IntoIterator<Item = AccountId>,
    ) -> Self {
        Self {
            account_id,
            account,
            sessions: sessions.into_iter().collect(),
            buffer: MessageBuffer::new(),
            pins: pins.into_iter().collect(),
            blocked: BTreeSet::new(),
            requested_identities: BTreeSet::new(),
            verified: verified.into_iter().collect(),
            sas: None,
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

    /// True when the current pin passed an interactive SAS verification.
    pub fn is_peer_verified(&self, peer: AccountId) -> bool {
        self.verified.contains(&peer)
    }

    /// Verified peers, for the caller to persist.
    pub fn verified_peers(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.verified.iter().copied()
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

    /// Encrypt a text message with the existing session.
    pub fn send_text(&mut self, peer: AccountId, text: &str) -> Result<Vec<Action>, CoreError> {
        let body = MessageBody::text(text).map_err(|_| CoreError::BadBody)?;
        self.send_body(peer, &body)
    }

    /// Encrypt a message body (text, image or a SAS verification frame) with the existing session.
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

    /// Start an interactive SAS verification with a pinned peer (D28).
    pub fn start_sas(&mut self, peer: AccountId) -> Result<Vec<Action>, CoreError> {
        if self.sas.is_some() {
            return Err(CoreError::SasInProgress);
        }
        if !self.pins.contains_key(&peer) {
            return Err(CoreError::NoPin(peer));
        }
        if !self.sessions.contains_key(&peer) {
            return Err(CoreError::NoSession(peer));
        }

        let sas = Sas::new();
        let public_key = *sas.public_key().as_bytes();
        let mut actions = self.send_sas_message(peer, SasMessage::Start { public_key })?;
        self.sas = Some(SasSession {
            peer,
            state: SasState::WaitingForPeer(sas),
        });
        actions.insert(0, Action::SasStarted { peer });
        Ok(actions)
    }

    /// Confirm the displayed code on this side and send the identity MAC.
    pub fn confirm_sas(&mut self, peer: AccountId) -> Result<Vec<Action>, CoreError> {
        let Some(session) = self.sas.take() else {
            return Err(CoreError::SasNotReady);
        };
        if session.peer != peer {
            self.sas = Some(session);
            return Err(CoreError::SasNotReady);
        }
        let SasState::AwaitingPeerConfirm {
            established,
            peer_confirmed,
        } = session.state
        else {
            self.sas = Some(session);
            return Err(CoreError::SasNotReady);
        };

        let mac = match self.sas_mac(peer, &established) {
            Ok(mac) => mac,
            Err(error) => {
                self.sas = Some(SasSession {
                    peer,
                    state: SasState::AwaitingPeerConfirm {
                        established,
                        peer_confirmed,
                    },
                });
                return Err(error);
            }
        };

        let mut actions = match self.send_sas_message(
            peer,
            SasMessage::Mac {
                mac: mac.to_base64(),
            },
        ) {
            Ok(actions) => actions,
            Err(error) => {
                self.sas = Some(SasSession {
                    peer,
                    state: SasState::AwaitingPeerConfirm {
                        established,
                        peer_confirmed,
                    },
                });
                return Err(error);
            }
        };
        actions.push(Action::SasLocalConfirmed { peer });

        if peer_confirmed {
            self.verified.insert(peer);
            self.sas = None;
            actions.push(Action::SasVerified { peer });
            actions.push(Action::Persist);
        } else {
            self.sas = Some(SasSession {
                peer,
                state: SasState::AwaitingPeerMac { established },
            });
        }
        Ok(actions)
    }

    /// Abort a SAS verification and tell the peer.
    pub fn cancel_sas(&mut self, peer: AccountId) -> Vec<Action> {
        if !self
            .sas
            .as_ref()
            .is_some_and(|session| session.peer == peer)
        {
            return Vec::new();
        }
        self.sas = None;
        let mut actions = self
            .send_sas_message(peer, SasMessage::Cancel)
            .unwrap_or_default();
        actions.push(Action::SasCancelled { peer });
        actions
    }

    /// Emergency wipe: clear the plaintext buffer, sessions and in-flight SAS state
    /// (vodozemac key types wipe themselves on drop).
    pub fn wipe(&mut self) {
        self.buffer.clear();
        self.sessions.clear();
        self.sas = None;
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

    fn send_sas_message(
        &mut self,
        peer: AccountId,
        message: SasMessage,
    ) -> Result<Vec<Action>, CoreError> {
        self.send_body(peer, &MessageBody::Sas(message))
    }

    /// Handle one SAS verification frame decrypted from the peer.
    fn handle_sas_message(&mut self, from: AccountId, message: SasMessage) -> Vec<Action> {
        if !self.pins.contains_key(&from) {
            // The peer started verification before we pinned it: fetch the directory
            // identity and ignore this frame. The peer can retry after the pin arrives.
            if self.requested_identities.insert(from) {
                return vec![Action::Send(Frame::FetchIdentity { account_id: from })];
            }
            return Vec::new();
        }

        match message {
            SasMessage::Start { public_key } => self.handle_sas_start(from, public_key),
            SasMessage::PublicKey { public_key } => self.handle_sas_public_key(from, public_key),
            SasMessage::Mac { mac } => self.handle_sas_mac(from, &mac),
            SasMessage::Cancel => {
                if self
                    .sas
                    .as_ref()
                    .is_some_and(|session| session.peer == from)
                {
                    self.sas = None;
                    vec![Action::SasCancelled { peer: from }]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn handle_sas_start(&mut self, from: AccountId, public_key: [u8; 32]) -> Vec<Action> {
        // A simultaneous start reuses our own ephemeral key as the responder key.
        let sas = match self.sas.take() {
            None => Sas::new(),
            Some(SasSession {
                peer,
                state: SasState::WaitingForPeer(sas),
            }) if peer == from => sas,
            Some(existing) => {
                self.sas = Some(existing);
                return Vec::new();
            }
        };

        let our_public_key = *sas.public_key().as_bytes();
        let Ok(established) = sas.diffie_hellman(Curve25519PublicKey::from_bytes(public_key))
        else {
            return vec![Action::SasFailed { peer: from }];
        };
        let mut actions = match self.send_sas_message(
            from,
            SasMessage::PublicKey {
                public_key: our_public_key,
            },
        ) {
            Ok(actions) => actions,
            Err(_) => return vec![Action::SasFailed { peer: from }],
        };
        actions.push(sas_code(from, &established));
        self.sas = Some(SasSession {
            peer: from,
            state: SasState::AwaitingPeerConfirm {
                established,
                peer_confirmed: false,
            },
        });
        actions
    }

    fn handle_sas_public_key(&mut self, from: AccountId, public_key: [u8; 32]) -> Vec<Action> {
        let Some(SasSession {
            peer,
            state: SasState::WaitingForPeer(sas),
        }) = self.sas.take()
        else {
            return Vec::new();
        };
        if peer != from {
            self.sas = Some(SasSession {
                peer,
                state: SasState::WaitingForPeer(sas),
            });
            return Vec::new();
        }

        let Ok(established) = sas.diffie_hellman(Curve25519PublicKey::from_bytes(public_key))
        else {
            return vec![Action::SasFailed { peer: from }];
        };
        let code = sas_code(from, &established);
        self.sas = Some(SasSession {
            peer: from,
            state: SasState::AwaitingPeerConfirm {
                established,
                peer_confirmed: false,
            },
        });
        vec![code]
    }

    fn handle_sas_mac(&mut self, from: AccountId, mac: &str) -> Vec<Action> {
        let Some(session) = self.sas.take() else {
            return Vec::new();
        };
        if session.peer != from {
            self.sas = Some(session);
            return Vec::new();
        }

        let input = match self.sas_mac_input(from) {
            // Bind the MAC to the sender: a peer cannot reflect our own MAC back to us.
            Ok(input) => format!("{from}:{input}"),
            Err(_) => return vec![Action::SasFailed { peer: from }],
        };
        let Ok(peer_mac) = Mac::from_base64(mac) else {
            return vec![Action::SasFailed { peer: from }];
        };
        let valid = match &session.state {
            SasState::AwaitingPeerConfirm { established, .. }
            | SasState::AwaitingPeerMac { established } => established
                .verify_mac(&input, SAS_MAC_INFO, &peer_mac)
                .is_ok(),
            SasState::WaitingForPeer(_) => {
                self.sas = Some(session);
                return Vec::new();
            }
        };
        if !valid {
            return vec![Action::SasFailed { peer: from }];
        }

        match session.state {
            SasState::AwaitingPeerConfirm { established, .. } => {
                self.sas = Some(SasSession {
                    peer: from,
                    state: SasState::AwaitingPeerConfirm {
                        established,
                        peer_confirmed: true,
                    },
                });
                vec![Action::SasPeerConfirmed { peer: from }]
            }
            SasState::AwaitingPeerMac { .. } => {
                self.verified.insert(from);
                vec![Action::SasVerified { peer: from }, Action::Persist]
            }
            SasState::WaitingForPeer(_) => unreachable!(),
        }
    }

    fn sas_mac(&self, peer: AccountId, established: &EstablishedSas) -> Result<Mac, CoreError> {
        // The sender-account prefix makes the two MACs directional (no reflection).
        let input = format!("{}:{}", self.account_id, self.sas_mac_input(peer)?);
        Ok(established.calculate_mac(&input, SAS_MAC_INFO))
    }

    /// Canonical MAC input binding both account IDs and both identity key pairs.
    /// Sorting by account ID makes both sides compute the same string.
    fn sas_mac_input(&self, peer: AccountId) -> Result<String, CoreError> {
        let peer_pin = self.pins.get(&peer).ok_or(CoreError::NoPin(peer))?;
        let own = self.account.identity_keys();
        let mut parties = [
            (
                self.account_id,
                *own.ed25519.as_bytes(),
                *own.curve25519.as_bytes(),
            ),
            (peer, peer_pin.ed25519_pub, peer_pin.curve25519_pub),
        ];
        parties.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

        let mut bytes = Vec::with_capacity(2 * (16 + 32 + 32));
        for (account, ed25519, curve25519) in parties {
            bytes.extend_from_slice(account.as_bytes());
            bytes.extend_from_slice(&ed25519);
            bytes.extend_from_slice(&curve25519);
        }
        Ok(hex(&bytes))
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
                if self
                    .sas
                    .as_ref()
                    .is_some_and(|session| session.peer == peer)
                {
                    self.sas = None;
                }
                let mut actions = vec![Action::PeerKeyChanged {
                    peer,
                    pinned,
                    observed: Some(observed),
                }];
                // A changed identity invalidates an earlier SAS verification.
                if self.verified.remove(&peer) {
                    actions.push(Action::Persist);
                }
                actions
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
            if self
                .sas
                .as_ref()
                .is_some_and(|session| session.peer == from)
            {
                self.sas = None;
            }
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
                let mut actions = identity_actions;
                match body {
                    MessageBody::Sas(message) => {
                        actions.extend(self.handle_sas_message(from, message));
                    }
                    body => {
                        let dropped_images = self.buffer.push_received(ReceivedMessage {
                            from,
                            body: body.clone(),
                        });
                        actions.push(Action::Received {
                            msg_id: msg_id.clone(),
                            from,
                            body,
                            dropped_images,
                        });
                    }
                }
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

/// Build the user-visible SAS code derived from the established shared secret.
fn sas_code(peer: AccountId, established: &EstablishedSas) -> Action {
    let code = established.bytes(SAS_INFO);
    Action::SasCode {
        peer,
        emojis: code.emoji_indices(),
        decimals: code.decimals(),
    }
}

/// Lowercase hex, used for the canonical MAC input string.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    text
}
