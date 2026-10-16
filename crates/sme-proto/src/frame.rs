//! M2 线路帧：控制帧（注册 / 登录 / 预密钥）与 Olm 消息信封。
//!
//! 信封的 `payload` 是 `OlmMessage`（pre-key 或 normal）的原始字节；
//! 消息序号、nonce 等由 Olm 内部管理，不在这层出现（plan.md §6.3 已据此修订）。

use serde::{Deserialize, Serialize};

use crate::account_id::AccountId;
use crate::{
    MAX_ENVELOPE_PAYLOAD, MAX_ERROR_DETAIL_LEN, MAX_KEY_ID_LEN, MAX_MSG_ID_LEN,
    MAX_PREKEYS_PER_UPLOAD, MAX_SESSION_ID_LEN, PROTOCOL_VERSION, ProtoError,
};

/// 注册时提交的 Argon2id 参数（服务端按 docs/INFRA.md §3 存成 JSONB）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// 首次注册：身份公钥、客户端生成的口令盐与 KDF 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub account_id: AccountId,
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
}

/// Ed25519 签名（64 字节）。serde 只对 `[u8; 32]` 及以下实现了数组编解码，所以这里用
/// `serialize_bytes` 手写一份固定长度实现。
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

/// 上传的一条一次性预密钥。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyUpload {
    pub key_id: String,
    pub public_key: [u8; 32],
}

/// 服务端交给发起方的预密钥 bundle；一次性预密钥取出即从服务端删除。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub account_id: AccountId,
    pub ed25519_pub: [u8; 32],
    pub curve25519_pub: [u8; 32],
    pub one_time_key_id: String,
    pub one_time_key: [u8; 32],
}

/// Olm 消息种类，对应 `vodozemac::olm::OlmMessage`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OlmMessageKind {
    PreKey,
    Normal,
}

/// 加密消息信封。服务端只读路由字段（`from` / `to`），其余一律照转。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u8,
    pub from: AccountId,
    pub to: AccountId,
    pub sid: String,
    pub kind: OlmMessageKind,
    pub payload: Vec<u8>,
}

/// 服务端返回的错误码。`detail` 只用于诊断，不承诺稳定。
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

/// 一份连接上的全部帧类型。
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

    /// 发送一条加密消息；服务端接管后回 `SendAck`（Q-ack）。
    Send(Envelope),
    /// 服务端投递一条消息；`msg_id` 是 Valkey Stream 的条目 ID，接收方 D-ack 后服务端据此删除。
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
    /// 字段级校验；[`crate::encode`] 与 [`crate::decode`] 都会调用。
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
        // 上限防止注册时塞入荒谬参数（Argon2id 只在客户端跑，但服务端要存）
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
