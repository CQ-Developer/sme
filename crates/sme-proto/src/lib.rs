//! Wire protocol: control frames, Olm message envelope, version negotiation and postcard codec (D4c, D4d).
//!
//! - Strict decoding: reject trailing bytes, unknown enum variants and oversized fields; see [`MAX_FRAME_BYTES`].
//! - No cryptography here: `Envelope::payload` is raw Olm ciphertext and the server only routes by `to`.
//! - This crate must not use file / network / process APIs (I2 gate).

mod account_id;
mod body;
mod codec;
mod frame;

pub use account_id::AccountId;
pub use body::{
    MAX_IMAGE_BYTES, MAX_IMAGE_DIMENSION, MAX_SAS_MAC_LEN, MAX_TEXT_BYTES, MessageBody, SasMessage,
};
pub use codec::{decode, decode_envelope, encode, encode_envelope};
pub use frame::{
    Envelope, ErrorCode, Frame, KdfParams, OlmMessageKind, PreKeyBundle, PreKeyUpload,
    Registration, Signature,
};

/// Current wire protocol version, carried in the envelope's `v` field.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum frame size (docs/INFRA.md §5: gateway WSS limit 1.2MB).
pub const MAX_FRAME_BYTES: usize = 1_200_000;

/// Maximum payload per envelope, leaving room for a 1MB image plus Olm overhead.
pub const MAX_ENVELOPE_PAYLOAD: usize = 1_100_000;

/// Maximum `Envelope::sid` length.
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Maximum one-time prekeys per upload.
pub const MAX_PREKEYS_PER_UPLOAD: u16 = 100;

/// Maximum string length of a prekey `key_id`.
pub const MAX_KEY_ID_LEN: usize = 64;

/// Maximum `Frame::Error::detail` length.
pub const MAX_ERROR_DETAIL_LEN: usize = 512;

/// Maximum string length of a Valkey Stream entry ID (like `1700000000000-0`).
pub const MAX_MSG_ID_LEN: usize = 64;

/// Canonical login-signature payload: domain separator + account ID + challenge nonce.
///
/// Client and gateway must sign/verify the same bytes to prevent cross-account replay.
pub fn login_payload(account_id: &AccountId, nonce: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LOGIN_DOMAIN.len() + 16 + 32);
    payload.extend_from_slice(LOGIN_DOMAIN);
    payload.extend_from_slice(account_id.as_bytes());
    payload.extend_from_slice(nonce);
    payload
}

const LOGIN_DOMAIN: &[u8] = b"sme-login-v1";

/// Codec errors.
#[derive(Debug)]
pub enum ProtoError {
    Encode(postcard::Error),
    Decode(postcard::Error),
    TooLarge(usize),
    TrailingBytes(usize),
    InvalidFrame(&'static str),
    InvalidAccountId,
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(error) => write!(f, "postcard encode failed: {error}"),
            Self::Decode(error) => write!(f, "postcard decode failed: {error}"),
            Self::TooLarge(size) => write!(f, "frame too large: {size} bytes"),
            Self::TrailingBytes(count) => write!(f, "{count} trailing bytes after frame"),
            Self::InvalidFrame(reason) => write!(f, "invalid frame: {reason}"),
            Self::InvalidAccountId => write!(f, "invalid account id"),
        }
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) | Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_payload_binds_account_and_nonce() {
        let account = AccountId::random();
        let other = AccountId::random();
        let nonce = [7u8; 32];

        let payload = login_payload(&account, &nonce);
        assert!(payload.starts_with(b"sme-login-v1"));
        assert_eq!(payload.len(), 12 + 16 + 32);
        assert_ne!(payload, login_payload(&other, &nonce));
        assert_ne!(payload, login_payload(&account, &[8u8; 32]));
    }
}
