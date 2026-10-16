//! 账号 ID：128-bit 随机，base32 26 字符（D16），用于防用户名枚举。
//!
//! 编码使用 RFC 4648 的 `A–Z2–7` 字母表、不带 padding；解码拒绝非规范写法
//! （最后一字符的低位必须为 0），保证一个 ID 只有一个合法字符串。

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// 账号 ID 的字节长度。
pub const ACCOUNT_ID_LEN: usize = 16;

/// 账号 ID 的 base32 字符串长度。
pub const ACCOUNT_ID_BASE32_LEN: usize = 26;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 128-bit 随机的账号标识；服务端与客户端都只把它当作不透明字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId([u8; ACCOUNT_ID_LEN]);

impl AccountId {
    pub const fn from_bytes(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }

    /// 生成一个新的随机账号 ID。
    pub fn random() -> Self {
        let mut bytes = [0u8; ACCOUNT_ID_LEN];
        // RNG 不可用时宁可终止进程，也不要生成可预测的账号 ID。
        getrandom::fill(&mut bytes).expect("OS random source unavailable");
        Self(bytes)
    }

    pub fn to_base32(self) -> String {
        encode_base32(&self.0)
    }

    pub fn parse_base32(input: &str) -> Result<Self, ProtoError> {
        if input.len() != ACCOUNT_ID_BASE32_LEN {
            return Err(ProtoError::InvalidAccountId);
        }
        let decoded = decode_base32(input)?;
        let bytes: [u8; ACCOUNT_ID_LEN] = decoded
            .try_into()
            .map_err(|_| ProtoError::InvalidAccountId)?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base32())
    }
}

impl std::str::FromStr for AccountId {
    type Err = ProtoError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_base32(input)
    }
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

fn decode_base32(input: &str) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(ProtoError::InvalidAccountId),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    // 非规范编码：剩余位必须为 0，否则同一个 ID 会有多种写法。
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        return Err(ProtoError::InvalidAccountId);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(decode_base32("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(encode_base32(b"f"), "MY");
        assert_eq!(decode_base32("MY").unwrap(), b"f");
    }

    #[test]
    fn account_id_roundtrip() {
        let id = AccountId::random();
        let text = id.to_base32();
        assert_eq!(text.len(), ACCOUNT_ID_BASE32_LEN);
        assert_eq!(AccountId::parse_base32(&text).unwrap(), id);
        assert_eq!(text.parse::<AccountId>().unwrap(), id);
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(AccountId::parse_base32("").is_err());
        assert!(AccountId::parse_base32("AAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
        // 长度不对
        assert!(AccountId::parse_base32("AAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        // 非法字符（0/1/8/9 不在 base32 字母表里）
        assert!(AccountId::parse_base32("AAAAAAAAAAAAAAAAAAAAAAAA01").is_err());
        // 最后一位非规范（低 2 位不为 0）：'B' 的 index=1，所有合法 ID 的最后一位都不会是它
        let id = AccountId::random();
        let mut text = id.to_base32();
        text.pop();
        text.push('B');
        assert!(AccountId::parse_base32(&text).is_err());
    }
}
