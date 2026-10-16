//! postcard 编解码：严格拒绝多余字节与超限帧（D4d）。

use crate::{Frame, MAX_FRAME_BYTES, ProtoError};

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
