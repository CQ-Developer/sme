//! postcard codec: strictly reject trailing bytes and oversized frames (D4d).

use crate::{Envelope, Frame, MAX_FRAME_BYTES, ProtoError};

/// Encode one frame; fails on validation or size overflow and never emits an invalid frame.
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtoError> {
    frame.validate()?;
    let bytes = postcard::to_allocvec(frame).map_err(ProtoError::Encode)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// Decode one frame; `postcard::from_bytes` ignores trailing bytes, so this uses `take_from_bytes` and rejects them explicitly.
pub fn decode(bytes: &[u8]) -> Result<Frame, ProtoError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    let (frame, remainder) =
        postcard::take_from_bytes::<Frame>(bytes).map_err(ProtoError::Decode)?;
    if !remainder.is_empty() {
        return Err(ProtoError::TrailingBytes(remainder.len()));
    }
    frame.validate()?;
    Ok(frame)
}

/// Encode an [`Envelope`]; Valkey Streams store messages as one blob.
pub fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, ProtoError> {
    envelope.validate()?;
    let bytes = postcard::to_allocvec(envelope).map_err(ProtoError::Encode)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// Decode the output of [`encode_envelope`], rejecting trailing bytes.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, ProtoError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    let (envelope, remainder) =
        postcard::take_from_bytes::<Envelope>(bytes).map_err(ProtoError::Decode)?;
    if !remainder.is_empty() {
        return Err(ProtoError::TrailingBytes(remainder.len()));
    }
    envelope.validate()?;
    Ok(envelope)
}
