//! Account IDs: 128-bit random, 26 base32 characters (D16), preventing username enumeration.
//!
//! Encoding uses the RFC 4648 `A-Z2-7` alphabet without padding; decoding rejects non-canonical forms
//! (the low bits of the last character must be zero) so each ID has exactly one valid spelling.

use serde::{Deserialize, Serialize};

use crate::ProtoError;

/// Byte length of an account ID.
pub const ACCOUNT_ID_LEN: usize = 16;

/// Base32 string length of an account ID.
pub const ACCOUNT_ID_BASE32_LEN: usize = 26;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 128-bit random account identifier; both server and client treat it as an opaque string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId([u8; ACCOUNT_ID_LEN]);

impl AccountId {
    pub const fn from_bytes(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }

    /// Generate a new random account ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; ACCOUNT_ID_LEN];
        // If the RNG is unavailable, abort rather than generate a predictable account ID.
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

    // Non-canonical encoding: leftover bits must be zero, or one ID would have several spellings.
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
        // Wrong length
        assert!(AccountId::parse_base32("AAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
        // Invalid characters (0/1/8/9 are not in the base32 alphabet)
        assert!(AccountId::parse_base32("AAAAAAAAAAAAAAAAAAAAAAAA01").is_err());
        // Non-canonical last character (low 2 bits non-zero): 'B' has index=1 and can never end a valid ID
        let id = AccountId::random();
        let mut text = id.to_base32();
        text.pop();
        text.push('B');
        assert!(AccountId::parse_base32(&text).is_err());
    }
}
