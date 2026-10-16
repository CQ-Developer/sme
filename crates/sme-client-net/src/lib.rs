//! WebSocket 传输：客户端唯一允许网络的 crate（plan.md §5）。
//!
//! 只负责把 [`sme_proto::Frame`] 编码后发出、把收到的字节解码成帧；
//! 不做加密、不持有会话状态、不落盘。

use futures_util::{SinkExt, StreamExt};
use sme_proto::{Frame, ProtoError, decode, encode};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

/// 一条 WebSocket 连接。
pub struct Transport {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

#[derive(Debug)]
pub enum NetError {
    Connect(tokio_tungstenite::tungstenite::Error),
    Transport(tokio_tungstenite::tungstenite::Error),
    Protocol(ProtoError),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "websocket connect failed: {error}"),
            Self::Transport(error) => write!(f, "websocket transport failed: {error}"),
            Self::Protocol(error) => write!(f, "protocol error: {error}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(error) | Self::Transport(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}

impl From<ProtoError> for NetError {
    fn from(error: ProtoError) -> Self {
        Self::Protocol(error)
    }
}

impl Transport {
    pub async fn connect(url: &str) -> Result<Self, NetError> {
        let (socket, _) = connect_async(url).await.map_err(NetError::Connect)?;
        Ok(Self { socket })
    }

    pub async fn send(&mut self, frame: &Frame) -> Result<(), NetError> {
        let bytes = encode(frame)?;
        self.socket
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(NetError::Transport)
    }

    /// 收到下一帧；连接正常关闭时返回 `Ok(None)`。
    pub async fn recv(&mut self) -> Result<Option<Frame>, NetError> {
        loop {
            match self.socket.next().await {
                None => return Ok(None),
                Some(Err(error)) => return Err(NetError::Transport(error)),
                Some(Ok(Message::Binary(bytes))) => return Ok(Some(decode(&bytes)?)),
                Some(Ok(Message::Ping(payload))) => {
                    self.socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(NetError::Transport)?;
                }
                Some(Ok(Message::Close(_))) => return Ok(None),
                Some(Ok(_)) => continue,
            }
        }
    }
}
