//! M2 wire frames: control frames (register / login / prekeys) and the Olm message envelope.
//!
//! The envelope `payload` holds raw `OlmMessage` bytes (pre-key or normal);
//! Message indices, nonces and friends are managed inside Olm and never appear here (plan.md §6.3 revised accordingly).

use serde::{Deserialize, Serialize};

use crate::account_id::AccountId;
use crate::{
    MAX_ENVELOPE_PAYLOAD, MAX_ERROR_DETAIL_LEN, MAX_KEY_ID_LEN, MAX_MSG_ID_LEN,
    MAX_PREKEYS_PER_UPLOAD, MAX_SESSION_ID_LEN, PROTOCOL_VERSION, ProtoError,
};

/// Argon2id parameters submitted at registration (stored as JSONB per docs/INFRA.md §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// First registration: identity public keys plus client-generated password salt and KDF parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub account_id: AccountId,
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
}

/// Ed25519 signature (64 bytes). serde only implements array codecs up to `[u8; 32]`, so this uses
/// a hand-written fixed-length implementation via `serialize_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; Self::LEN]);

impl Signature {
    pub const LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;

        impl serde::de::Visitor<'_> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                let array = <[u8; Signature::LEN]>::try_from(bytes)
                    .map_err(|_| E::invalid_length(bytes.len(), &self))?;
                Ok(Signature(array))
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

/// One uploaded one-time prekey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyUpload {
    pub key_id: String,
    pub public_key: [u8; 32],
}

/// Prekey bundle handed to the initiator; one-time keys are deleted server-side when taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub account_id: AccountId,
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
    pub one_time_key_id: String,
    pub one_time_key: [u8; 32],
}

/// Olm message kind, mirroring `vodozemac::olm::OlmMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OlmMessageKind {
    PreKey,
    Normal,
}

/// Encrypted message envelope. The server reads only routing fields (`from` / `to`) and forwards the rest verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub from: AccountId,
    pub to: AccountId,
    pub sid: String,
    pub kind: OlmMessageKind,
    pub payload: Vec<u8>,
}

/// Server error codes. `detail` is diagnostic only and not stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadFrame,
    NotAuthenticated,
    AlreadyRegistered,
    UnknownAccount,
    ChallengeExpired,
    BadSignature,
    SessionReplaced,
    PreKeyUnavailable,
    QueueFull,
    RateLimited,
    Internal,
}

/// Every frame type carried over one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    Register(Registration),
    RegisterAck {
        account_id: AccountId,
    },

    ChallengeRequest {
        account_id: AccountId,
    },
    Challenge {
        nonce: [u8; 32],
    },
    Login {
        account_id: AccountId,
        nonce: [u8; 32],
        signature: Signature,
    },
    LoginAck {
        account_id: AccountId,
    },

    UploadPreKeys {
        prekeys: Vec<PreKeyUpload>,
    },
    UploadPreKeysAck {
        stored: u16,
    },
    FetchPreKey {
        account_id: AccountId,
    },
    PreKeyBundle(PreKeyBundle),

    /// Send one encrypted message; the server replies `SendAck` (Q-ack) once it takes custody.
    Send(Envelope),
    /// Server delivers a message; `msg_id` is the Valkey Stream entry ID that the server deletes on D-ack.
    Deliver {
        msg_id: String,
        envelope: Envelope,
    },
    SendAck {
        msg_id: String,
    },
    DeliverAck {
        msg_id: String,
    },

    Error {
        code: ErrorCode,
        detail: String,
    },
}

impl Frame {
    /// Field-level validation, called by both [`crate::encode`] and [`crate::decode`].
    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Register(registration) => registration.validate(),
            Self::UploadPreKeys { prekeys } => {
                if prekeys.len() > usize::from(MAX_PREKEYS_PER_UPLOAD) {
                    return Err(ProtoError::InvalidFrame("too many prekeys"));
                }
                for prekey in prekeys {
                    prekey.validate()?;
                }
                Ok(())
            }
            Self::PreKeyBundle(bundle) => bundle.validate(),
            Self::Send(envelope) => envelope.validate(),
            Self::Deliver { msg_id, envelope } => {
                validate_msg_id(msg_id)?;
                envelope.validate()
            }
            Self::SendAck { msg_id } | Self::DeliverAck { msg_id } => validate_msg_id(msg_id),
            Self::Error { detail, .. } => {
                if detail.len() > MAX_ERROR_DETAIL_LEN {
                    return Err(ProtoError::InvalidFrame("error detail too long"));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl Registration {
    fn validate(&self) -> Result<(), ProtoError> {
        let params = self.kdf_params;
        if params.m_cost == 0 || params.t_cost == 0 || params.p_cost == 0 {
            return Err(ProtoError::InvalidFrame("kdf params must be non-zero"));
        }
        // Caps stop absurd parameters at registration (Argon2id runs client-side, but the server stores them)
        if params.m_cost > 1 << 18 || params.t_cost > 64 || params.p_cost > 16 {
            return Err(ProtoError::InvalidFrame("kdf params out of range"));
        }
        Ok(())
    }
}

impl PreKeyUpload {
    fn validate(&self) -> Result<(), ProtoError> {
        if self.key_id.is_empty() || self.key_id.len() > MAX_KEY_ID_LEN {
            return Err(ProtoError::InvalidFrame("bad prekey id length"));
        }
        Ok(())
    }
}

impl PreKeyBundle {
    fn validate(&self) -> Result<(), ProtoError> {
        if self.one_time_key_id.is_empty() || self.one_time_key_id.len() > MAX_KEY_ID_LEN {
            return Err(ProtoError::InvalidFrame("bad one-time key id length"));
        }
        Ok(())
    }
}

fn validate_msg_id(msg_id: &str) -> Result<(), ProtoError> {
    if msg_id.is_empty() || msg_id.len() > MAX_MSG_ID_LEN {
        return Err(ProtoError::InvalidFrame("bad stream entry id"));
    }
    Ok(())
}

impl Envelope {
    pub(crate) fn validate(&self) -> Result<(), ProtoError> {
        if self.v != PROTOCOL_VERSION {
            return Err(ProtoError::InvalidFrame("unsupported envelope version"));
        }
        if self.sid.is_empty() || self.sid.len() > MAX_SESSION_ID_LEN {
            return Err(ProtoError::InvalidFrame("bad session id length"));
        }
        if self.payload.is_empty() || self.payload.len() > MAX_ENVELOPE_PAYLOAD {
            return Err(ProtoError::InvalidFrame("bad payload length"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(payload_len: usize) -> Envelope {
        Envelope {
            v: PROTOCOL_VERSION,
            from: AccountId::random(),
            to: AccountId::random(),
            sid: "session-1".to_string(),
            kind: OlmMessageKind::Normal,
            payload: vec![0x42; payload_len],
        }
    }

    #[test]
    fn rejects_wrong_version_and_empty_payload() {
        let mut message = envelope(1);
        message.v = PROTOCOL_VERSION + 1;
        assert!(Frame::Send(message).validate().is_err());

        let mut message = envelope(1);
        message.payload.clear();
        assert!(Frame::Send(message).validate().is_err());
    }

    #[test]
    fn rejects_too_many_prekeys() {
        let prekeys: Vec<_> = (0..=MAX_PREKEYS_PER_UPLOAD)
            .map(|i| PreKeyUpload {
                key_id: format!("k{i}"),
                public_key: [1u8; 32],
            })
            .collect();
        assert!(Frame::UploadPreKeys { prekeys }.validate().is_err());
    }
}
