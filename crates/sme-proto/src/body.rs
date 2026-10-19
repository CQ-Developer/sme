//! Client-side message body, serialized inside the Olm plaintext.
//!
//! The gateway never sees this: it only routes the encrypted envelope (I1/D11).
//! v1 supports text (<= 16KB), one JPEG image (<= 1MB, prepared by `sme-media`) and opaque
//! interactive SAS verification frames (D28). SAS frames never enter the chat buffer.

use serde::{Deserialize, Serialize};

use crate::{MAX_FRAME_BYTES, ProtoError};

/// Maximum text size (plan.md D21).
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Maximum compressed image size (plan.md D21 / §7).
pub const MAX_IMAGE_BYTES: usize = 1_000_000;

/// Maximum image edge after client-side compression (plan.md §7).
pub const MAX_IMAGE_DIMENSION: u32 = 2048;

/// Maximum base64 MAC length in a SAS verification message.
pub const MAX_SAS_MAC_LEN: usize = 128;

/// Interactive SAS verification frames, carried inside the Olm plaintext (D28).
///
/// The gateway never sees these: they are part of [`MessageBody`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SasMessage {
    /// Initiator's ephemeral Curve25519 public key.
    Start { public_key: [u8; 32] },
    /// Responder's ephemeral Curve25519 public key.
    PublicKey { public_key: [u8; 32] },
    /// MAC over both parties' identity keys, sent after the local user confirmed the code.
    Mac { mac: String },
    /// Abort the verification.
    Cancel,
}

impl SasMessage {
    fn validate(&self) -> Result<(), ProtoError> {
        if let Self::Mac { mac } = self
            && (mac.is_empty() || mac.len() > MAX_SAS_MAC_LEN)
        {
            return Err(ProtoError::InvalidFrame("bad SAS MAC length"));
        }
        Ok(())
    }
}

/// Plaintext message body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageBody {
    Text {
        text: String,
    },
    /// Always JPEG: the sender re-encodes, the receiver never sees other formats (§7).
    Image {
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
    /// Interactive SAS verification control frame; never buffered as a chat message.
    Sas(SasMessage),
}

impl MessageBody {
    /// Build a text body with validation.
    pub fn text(text: impl Into<String>) -> Result<Self, ProtoError> {
        let body = Self::Text { text: text.into() };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), ProtoError> {
        match self {
            Self::Text { text } => {
                if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                    return Err(ProtoError::InvalidFrame("bad text length"));
                }
            }
            Self::Image {
                width,
                height,
                bytes,
            } => {
                if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
                    return Err(ProtoError::InvalidFrame("bad image length"));
                }
                if *width == 0
                    || *height == 0
                    || *width > MAX_IMAGE_DIMENSION
                    || *height > MAX_IMAGE_DIMENSION
                {
                    return Err(ProtoError::InvalidFrame("bad image dimensions"));
                }
            }
            Self::Sas(message) => message.validate()?,
        }
        Ok(())
    }

    /// Size of the image payload, if this is an image.
    pub fn image_bytes_len(&self) -> Option<usize> {
        match self {
            Self::Image { bytes, .. } => Some(bytes.len()),
            Self::Text { .. } | Self::Sas(_) => None,
        }
    }

    /// Encode for inclusion in the Olm plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        self.validate()?;
        let bytes = postcard::to_allocvec(self).map_err(ProtoError::Encode)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ProtoError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Decode, rejecting trailing bytes and invalid bodies.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ProtoError::TooLarge(bytes.len()));
        }
        let (body, remainder) =
            postcard::take_from_bytes::<Self>(bytes).map_err(ProtoError::Decode)?;
        if !remainder.is_empty() {
            return Err(ProtoError::TrailingBytes(remainder.len()));
        }
        body.validate()?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip_and_limits() {
        let body = MessageBody::text("hello").unwrap();
        let encoded = body.encode().unwrap();
        assert_eq!(MessageBody::decode(&encoded).unwrap(), body);

        assert!(MessageBody::text("").is_err());
        assert!(MessageBody::text("x".repeat(MAX_TEXT_BYTES + 1)).is_err());
        assert!(MessageBody::text("x".repeat(MAX_TEXT_BYTES)).is_ok());
    }

    #[test]
    fn image_limits_are_enforced() {
        let ok = MessageBody::Image {
            width: 100,
            height: 50,
            bytes: vec![1, 2, 3],
        };
        assert!(ok.encode().is_ok());

        let too_wide = MessageBody::Image {
            width: MAX_IMAGE_DIMENSION + 1,
            height: 1,
            bytes: vec![1],
        };
        assert!(too_wide.encode().is_err());

        let too_big = MessageBody::Image {
            width: 1,
            height: 1,
            bytes: vec![0; MAX_IMAGE_BYTES + 1],
        };
        assert!(too_big.encode().is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = MessageBody::text("hi").unwrap().encode().unwrap();
        encoded.push(0);
        assert!(MessageBody::decode(&encoded).is_err());
    }

    #[test]
    fn sas_messages_roundtrip_and_validate_macs() {
        let start = MessageBody::Sas(SasMessage::Start {
            public_key: [7u8; 32],
        });
        let encoded = start.encode().unwrap();
        assert_eq!(MessageBody::decode(&encoded).unwrap(), start);

        let bad = MessageBody::Sas(SasMessage::Mac {
            mac: "".to_string(),
        });
        assert!(bad.encode().is_err());
        assert!(bad.validate().is_err());
    }
}
