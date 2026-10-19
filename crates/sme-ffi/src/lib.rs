//! uniffi bindings for the mobile shells (D4b).
//!
//! One interface generates Swift and Kotlin bindings; the mobile apps own the UI
//! and lifecycle, this layer exposes the headless [`sme_client::Session`] and the
//! `sme-media` pipeline.
//!
//! Generate bindings with:
//! ```text
//! cargo build -p sme-ffi
//! cargo run -p sme-ffi --features cli --bin uniffi-bindgen -- \
//!     generate --library target/debug/libsme_ffi.so --language swift --out-dir out/swift
//! ```

uniffi::setup_scaffolding!("sme");

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use sme_client::{Event, ReceivedKind, Session, SessionError};
use sme_media::{MediaError, prepare_image};
use sme_proto::{AccountId, MessageBody};

/// Flat error type: the message is all the shell needs.
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    Generic { message: String },
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic { message } => f.write_str(message),
        }
    }
}

impl From<SessionError> for FfiError {
    fn from(error: SessionError) -> Self {
        Self::Generic {
            message: error.to_string(),
        }
    }
}

impl From<MediaError> for FfiError {
    fn from(error: MediaError) -> Self {
        Self::Generic {
            message: error.to_string(),
        }
    }
}

fn invalid(detail: &str) -> FfiError {
    FfiError::Generic {
        message: detail.to_string(),
    }
}

fn parse_peer(text: &str) -> Result<AccountId, FfiError> {
    text.parse::<AccountId>()
        .map_err(|_| invalid("invalid account id"))
}

/// A processed image ready to send (always JPEG, metadata stripped).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PreparedImage {
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
}

/// Compress and strip metadata from an image (I12); the shell can preview `bytes`
/// before sending them with [`Client::send_image`].
#[uniffi::export]
pub fn prepare_send_image(input: Vec<u8>) -> Result<PreparedImage, FfiError> {
    let prepared = prepare_image(&input)?;
    Ok(PreparedImage {
        width: prepared.width,
        height: prepared.height,
        bytes: prepared.bytes,
    })
}

/// What kind of message arrived.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum MessageKind {
    Text {
        text: String,
    },
    Image {
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
}

/// Events surfaced to the shell.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum ClientEvent {
    Registered,
    Ready,
    PreKeysUploaded {
        stored: u16,
    },
    SessionEstablished {
        peer: String,
    },
    Sent {
        msg_id: String,
    },
    Received {
        from: String,
        kind: MessageKind,
        dropped_images: u32,
    },
    DecryptFailed {
        from: String,
    },
    ServerError {
        code: String,
        detail: String,
    },
    ProtocolError {
        detail: String,
    },
    PeerPinned {
        peer: String,
        ed25519: String,
        curve25519: String,
    },
    PeerKeyChanged {
        peer: String,
        pinned_ed25519: String,
        pinned_curve25519: String,
        observed_ed25519: Option<String>,
        observed_curve25519: Option<String>,
    },
    PeerKeyConfirmed {
        peer: String,
    },
    SasStarted {
        peer: String,
    },
    SasCode {
        peer: String,
        /// Matrix SAS emoji indices (0..=63); map with the Matrix emoji table.
        emojis: Vec<u8>,
        /// Three decimal numbers to compare out of band.
        decimals: Vec<u16>,
    },
    SasPeerConfirmed {
        peer: String,
    },
    SasLocalConfirmed {
        peer: String,
    },
    SasVerified {
        peer: String,
    },
    SasFailed {
        peer: String,
    },
    SasCancelled {
        peer: String,
    },
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn to_ffi_event(event: Event) -> ClientEvent {
    match event {
        Event::Registered => ClientEvent::Registered,
        Event::Ready => ClientEvent::Ready,
        Event::PreKeysUploaded { stored } => ClientEvent::PreKeysUploaded { stored },
        Event::SessionEstablished { peer } => ClientEvent::SessionEstablished {
            peer: peer.to_base32(),
        },
        Event::Sent { msg_id } => ClientEvent::Sent { msg_id },
        Event::Received {
            from,
            kind,
            dropped_images,
        } => ClientEvent::Received {
            from: from.to_base32(),
            dropped_images: u32::try_from(dropped_images).unwrap_or(u32::MAX),
            kind: match kind {
                ReceivedKind::Text(text) => MessageKind::Text { text },
                ReceivedKind::Image {
                    width,
                    height,
                    bytes,
                } => MessageKind::Image {
                    width,
                    height,
                    bytes,
                },
            },
        },
        Event::DecryptFailed { from } => ClientEvent::DecryptFailed {
            from: from.to_base32(),
        },
        Event::ServerError { code, detail } => ClientEvent::ServerError {
            code: format!("{code:?}"),
            detail,
        },
        Event::ProtocolError { detail } => ClientEvent::ProtocolError {
            detail: detail.to_string(),
        },
        Event::PeerPinned { peer, pin } => ClientEvent::PeerPinned {
            peer: peer.to_base32(),
            ed25519: hex(&pin.ed25519_pub),
            curve25519: hex(&pin.curve25519_pub),
        },
        Event::PeerKeyChanged {
            peer,
            pinned,
            observed,
        } => ClientEvent::PeerKeyChanged {
            peer: peer.to_base32(),
            pinned_ed25519: hex(&pinned.ed25519_pub),
            pinned_curve25519: hex(&pinned.curve25519_pub),
            observed_ed25519: observed.as_ref().map(|pin| hex(&pin.ed25519_pub)),
            observed_curve25519: observed.as_ref().map(|pin| hex(&pin.curve25519_pub)),
        },
        Event::PeerKeyConfirmed { peer } => ClientEvent::PeerKeyConfirmed {
            peer: peer.to_base32(),
        },
        Event::SasStarted { peer } => ClientEvent::SasStarted {
            peer: peer.to_base32(),
        },
        Event::SasCode {
            peer,
            emojis,
            decimals,
        } => ClientEvent::SasCode {
            peer: peer.to_base32(),
            emojis: emojis.to_vec(),
            decimals: vec![decimals.0, decimals.1, decimals.2],
        },
        Event::SasPeerConfirmed { peer } => ClientEvent::SasPeerConfirmed {
            peer: peer.to_base32(),
        },
        Event::SasLocalConfirmed { peer } => ClientEvent::SasLocalConfirmed {
            peer: peer.to_base32(),
        },
        Event::SasVerified { peer } => ClientEvent::SasVerified {
            peer: peer.to_base32(),
        },
        Event::SasFailed { peer } => ClientEvent::SasFailed {
            peer: peer.to_base32(),
        },
        Event::SasCancelled { peer } => ClientEvent::SasCancelled {
            peer: peer.to_base32(),
        },
    }
}

/// One live, logged-in client session.
///
/// The shell polls [`Client::next_event`] (e.g. inside a coroutine) and reacts to
/// the events; all keys and the plaintext buffer stay inside Rust.
#[derive(uniffi::Object)]
pub struct Client {
    account_id: String,
    session: tokio::sync::Mutex<Session>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Open (or create) the keystore, connect to the gateway, register and log in.
    #[uniffi::constructor]
    pub async fn connect(
        server_url: String,
        keystore_path: String,
        password: String,
    ) -> Result<Arc<Self>, FfiError> {
        let session =
            Session::connect(&server_url, Path::new(&keystore_path), password.as_bytes()).await?;
        Ok(Arc::new(Self {
            account_id: session.account_id().to_base32(),
            session: tokio::sync::Mutex::new(session),
        }))
    }

    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }

    /// Wait for the next UI event.
    pub async fn next_event(&self) -> Result<ClientEvent, FfiError> {
        let mut session = self.session.lock().await;
        let event = session.next_event().await?;
        Ok(to_ffi_event(event))
    }

    pub async fn send_text(&self, peer: String, text: String) -> Result<(), FfiError> {
        let peer = parse_peer(&peer)?;
        let mut session = self.session.lock().await;
        session.send_text(peer, &text).await?;
        Ok(())
    }

    /// Compress (I12) and send an image; the payload never touches disk.
    pub async fn send_image(&self, peer: String, input: Vec<u8>) -> Result<(), FfiError> {
        let peer = parse_peer(&peer)?;
        let prepared = prepare_image(&input)?;
        let body = MessageBody::Image {
            width: prepared.width,
            height: prepared.height,
            bytes: prepared.bytes,
        };
        let mut session = self.session.lock().await;
        session.send_body(peer, &body).await?;
        Ok(())
    }

    /// Fetch the peer's prekey bundle; [`ClientEvent::SessionEstablished`] follows.
    pub async fn fetch_prekey(&self, peer: String) -> Result<(), FfiError> {
        let peer = parse_peer(&peer)?;
        let mut session = self.session.lock().await;
        session.fetch_prekey(peer).await?;
        Ok(())
    }

    pub async fn upload_prekeys(&self, count: u32) -> Result<(), FfiError> {
        let mut session = self.session.lock().await;
        session.upload_prekeys(count as usize).await?;
        Ok(())
    }

    /// Emergency wipe: clears the in-memory plaintext and sessions.
    pub async fn wipe_memory(&self) {
        self.session.lock().await.wipe_memory();
    }

    /// Dangerous: deletes the keystore and local config.
    pub async fn delete_keystore(&self) -> Result<(), FfiError> {
        let session = self.session.lock().await;
        session.delete_keystore()?;
        Ok(())
    }
}
