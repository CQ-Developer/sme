//! 线路信封、版本协商与错误类型，客户端与服务端共享（D4c、D4d）。
//!
//! M0 只固定协议版本；信封结构与 postcard 编解码在 M2 落地。
//! 本 crate 禁止文件 / 网络 / 进程 API（I2 门禁）；密码学代码不依赖 serde（D4d）。

/// 当前线路协议版本，对应信封的 `v` 字段。
pub const PROTOCOL_VERSION: u8 = 1;
