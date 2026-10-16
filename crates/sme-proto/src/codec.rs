//! postcard 编解码：严格拒绝多余字节与超限帧（D4d）。

use crate::{Envelope, Frame, MAX_FRAME_BYTES, ProtoError};

/// 编码一帧；字段校验或长度超限时失败，绝不发出非法帧。
pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtoError> {
    frame.validate()?;
    let bytes = postcard::to_allocvec(frame).map_err(ProtoError::Encode)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// 解码一帧；`postcard::from_bytes` 会忽略尾部字节，这里改用 `take_from_bytes` 显式拒绝。
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

/// 编码一个 [`Envelope`]；Valkey Stream 用它整体存放消息。
pub fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, ProtoError> {
    envelope.validate()?;
    let bytes = postcard::to_allocvec(envelope).map_err(ProtoError::Encode)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// 解码 [`encode_envelope`] 的输出，拒绝多余字节。
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
