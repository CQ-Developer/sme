//! 线路协议：控制帧、Olm 消息信封、版本协商与 postcard 编解码（D4c、D4d）。
//!
//! - 解码严格：拒绝多余字节、未知枚举分支与超限字段；单帧上限见 [`MAX_FRAME_BYTES`]。
//! - 密码学不在这里：`Envelope::payload` 是 Olm 密文的原始字节，服务端只按 `to` 转发。
//! - 本 crate 禁止文件 / 网络 / 进程 API（I2 门禁）。

mod account_id;
mod codec;
mod frame;

pub use account_id::AccountId;
pub use codec::{decode, encode};
pub use frame::{
    Envelope, ErrorCode, Frame, KdfParams, OlmMessageKind, PreKeyBundle, PreKeyUpload,
    Registration, Signature,
};

/// 当前线路协议版本，对应信封的 `v` 字段。
pub const PROTOCOL_VERSION: u8 = 1;

/// 单帧最大字节数（docs/INFRA.md §5：网关 WSS 消息上限 1.2MB）。
pub const MAX_FRAME_BYTES: usize = 1_200_000;

/// 单个信封密文载荷上限，留出 1MB 图片与 Olm 封装开销的余量。
pub const MAX_ENVELOPE_PAYLOAD: usize = 1_100_000;

/// `Envelope::sid` 长度上限。
pub const MAX_SESSION_ID_LEN: usize = 128;

/// 单次上传的一次性预密钥条数上限。
pub const MAX_PREKEYS_PER_UPLOAD: u16 = 100;

/// 预密钥 `key_id` 字符串长度上限。
pub const MAX_KEY_ID_LEN: usize = 64;

/// `Frame::Error::detail` 长度上限。
pub const MAX_ERROR_DETAIL_LEN: usize = 512;

/// 编解码错误。
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
