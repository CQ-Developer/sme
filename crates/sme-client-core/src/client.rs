//! 客户端核心状态机：Olm 握手、加解密、内存缓冲与持久化信号。
//!
//! 输入输出只有 [`sme_proto::Frame`] 与 [`Action`]：
//! - `Action::Send` 交给 `sme-client-net` 发送；
//! - `Action::Persist` 时调用方把 `account()` / `sessions()` 写进 keystore；
//! - 其余是给 UI 的事件。

use std::collections::BTreeMap;

use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, KdfParams, OlmMessageKind, PROTOCOL_VERSION,
    PreKeyUpload, Registration, Signature, login_payload,
};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, Message as OlmNormalMessage, OlmMessage, PreKeyMessage, Session, SessionConfig,
};

use crate::MessageBuffer;

/// 一条已解密、进入内存缓冲的消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMessage {
    pub from: AccountId,
    pub plaintext: Vec<u8>,
}

/// 交给调用方执行的动作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 立即通过 `sme-client-net` 发出。
    Send(Frame),
    /// 新解密出的明文（已进入内存缓冲）。
    Received {
        msg_id: u64,
        from: AccountId,
        plaintext: Vec<u8>,
    },
    /// 解密失败（如重复投递）；已回 D-ack，不显示。
    DecryptFailed {
        msg_id: u64,
        from: AccountId,
    },
    /// 收不到/看不懂的帧；只记录，不影响连接。
    ProtocolError {
        detail: &'static str,
    },
    Registered,
    /// 一次性预密钥已上传（`stored` 是服务端保存的总数）。
    PreKeysUploaded {
        stored: u16,
    },
    /// 与对端的 Olm 会话已建立。
    SessionEstablished {
        peer: AccountId,
    },
    /// 一条消息已被服务端接管（Q-ack）。
    Sent {
        msg_id: u64,
    },
    Ready,
    /// 账号或会话状态有变化；调用方应写 keystore。
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
    SessionCreation(vodozemac::olm::SessionCreationError),
    Encryption(vodozemac::olm::EncryptionError),
    Decryption(vodozemac::olm::DecryptionError),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSession(account) => write!(f, "no established olm session with {account}"),
            Self::BadEnvelope(reason) => write!(f, "bad envelope: {reason}"),
            Self::SessionCreation(error) => write!(f, "olm session creation failed: {error}"),
            Self::Encryption(error) => write!(f, "olm encryption failed: {error}"),
            Self::Decryption(error) => write!(f, "olm decryption failed: {error}"),
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

/// 客户端核心：身份、Olm 会话与明文缓冲。
pub struct Client {
    account_id: AccountId,
    account: Account,
    sessions: BTreeMap<AccountId, Session>,
    buffer: MessageBuffer<ReceivedMessage>,
}

impl Client {
    pub fn new(account_id: AccountId, account: Account) -> Self {
        Self {
            account_id,
            account,
            sessions: BTreeMap::new(),
            buffer: MessageBuffer::new(),
        }
    }

    /// 从 keystore 恢复身份与会话（M1 的持久化格式）。
    pub fn restore(
        account_id: AccountId,
        account: Account,
        sessions: impl IntoIterator<Item = (AccountId, Session)>,
    ) -> Self {
        Self {
            account_id,
            account,
            sessions: sessions.into_iter().collect(),
            buffer: MessageBuffer::new(),
        }
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    /// 已建立的会话与各自的对端，供调用方写入 keystore。
    pub fn sessions(&self) -> impl Iterator<Item = (AccountId, &Session)> {
        self.sessions.iter().map(|(peer, session)| (*peer, session))
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

    /// 生成一批一次性预密钥并标记为已发布；由调用方上传。
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

    /// 用现有会话加密一条文本/字节消息。
    pub fn send_text(
        &mut self,
        peer: AccountId,
        plaintext: &[u8],
    ) -> Result<Vec<Action>, CoreError> {
        let session = self
            .sessions
            .get_mut(&peer)
            .ok_or(CoreError::NoSession(peer))?;
        let message = session.encrypt(plaintext).map_err(CoreError::Encryption)?;

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

    /// 处理一帧服务端消息；返回调用方需要执行的动作。
    pub fn handle_frame(&mut self, frame: Frame) -> Vec<Action> {
        match frame {
            Frame::RegisterAck { .. } => vec![Action::Registered],

            Frame::Challenge { nonce } => {
                let signature = self.account.sign(login_payload(&self.account_id, &nonce));
                vec![Action::Send(Frame::Login {
                    account_id: self.account_id,
                    signature: Signature::from_bytes(signature.to_bytes()),
                })]
            }

            Frame::LoginAck { .. } => vec![Action::Ready],

            Frame::UploadPreKeysAck { stored } => vec![Action::PreKeysUploaded { stored }],

            Frame::SendAck { msg_id } => vec![Action::Sent { msg_id }],

            Frame::PreKeyBundle(bundle) => {
                match self.account.create_outbound_session(
                    SessionConfig::default(),
                    Curve25519PublicKey::from_bytes(bundle.curve25519_pub),
                    Curve25519PublicKey::from_bytes(bundle.one_time_key),
                ) {
                    Ok(session) => {
                        let peer = bundle.account_id;
                        self.sessions.insert(peer, session);
                        vec![Action::SessionEstablished { peer }, Action::Persist]
                    }
                    Err(_) => vec![Action::ProtocolError {
                        detail: "failed to create outbound session",
                    }],
                }
            }

            Frame::Deliver { msg_id, envelope } => self.handle_deliver(msg_id, envelope),

            Frame::Error { code, detail } => vec![Action::ServerError { code, detail }],

            _ => vec![],
        }
    }

    fn handle_deliver(&mut self, msg_id: u64, envelope: Envelope) -> Vec<Action> {
        let from = envelope.from;
        match self.decrypt(&envelope) {
            Ok((plaintext, session_changed)) => {
                self.buffer.push(ReceivedMessage {
                    from,
                    plaintext: plaintext.clone(),
                });

                let mut actions = vec![
                    Action::Received {
                        msg_id,
                        from,
                        plaintext,
                    },
                    Action::Send(Frame::DeliverAck { msg_id }),
                ];
                if session_changed {
                    actions.push(Action::Persist);
                }
                actions
            }
            Err(_) => vec![
                Action::DecryptFailed { msg_id, from },
                // 重复投递会消耗掉的消息密钥：也必须 D-ack，否则服务端会一直重投
                Action::Send(Frame::DeliverAck { msg_id }),
            ],
        }
    }

    /// 解密一个信封；返回 `(plaintext, 是否改动了本地状态)`。
    fn decrypt(&mut self, envelope: &Envelope) -> Result<(Vec<u8>, bool), CoreError> {
        if envelope.to != self.account_id {
            return Err(CoreError::BadEnvelope(
                "envelope addressed to another account",
            ));
        }
        let from = envelope.from;

        match envelope.kind {
            OlmMessageKind::PreKey => {
                // 重复投递或乱序：先试已有会话。
                if let Some(session) = self.sessions.get_mut(&from)
                    && let Ok(message) = PreKeyMessage::from_bytes(&envelope.payload)
                    && let Ok(plaintext) = session.decrypt(&OlmMessage::PreKey(message))
                {
                    return Ok((plaintext, true));
                }

                let pre_key = PreKeyMessage::from_bytes(&envelope.payload)
                    .map_err(|_| CoreError::BadEnvelope("bad pre-key message"))?;
                let identity_key = pre_key.identity_key();
                let inbound = self
                    .account
                    .create_inbound_session(SessionConfig::default(), identity_key, &pre_key)
                    .map_err(CoreError::SessionCreation)?;
                self.sessions.insert(from, inbound.session);
                Ok((inbound.plaintext, true))
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
                Ok((plaintext, true))
            }
        }
    }
}
