//! ratatui 参考客户端（M4）：`main.rs` 是 UI，[`session`] 是无 UI 的会话层。
//!
//! 明文只存在于 `sme-client-core` 的 10 条内存缓冲与渲染瞬间的 UI 字符串里，
//! 本 crate 不写任何消息到磁盘（I4）。

pub mod session;
