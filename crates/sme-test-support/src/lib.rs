//! 集成测试支撑：临时 Valkey 容器、临时目录与最小 WS 客户端。
//!
//! 只被 `sme-server` / `sme-client-tui` 的测试使用，不进入任何产品二进制。

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use sme_proto::{AccountId, Frame, Signature, decode, encode, login_payload};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use vodozemac::olm::Account;

static CONTAINER_SEQ: AtomicU64 = AtomicU64::new(0);

/// 一个由测试启动、进程退出时清理的 Valkey 容器。
pub struct ValkeyContainer {
    name: String,
    url: String,
    port: u16,
}

impl ValkeyContainer {
    /// 启动一个禁用持久化的 Valkey（tmpfs + `--save ""` + `--appendonly no`）。
    pub async fn ephemeral() -> Result<Self, String> {
        Self::start_with(true).await
    }

    /// 故意打开 AOF 的 Valkey，用于 I7 负例。
    pub async fn with_appendonly() -> Result<Self, String> {
        Self::start_with(false).await
    }

    async fn start_with(ephemeral: bool) -> Result<Self, String> {
        let port = free_port()?;
        let seq = CONTAINER_SEQ.fetch_add(1, Ordering::Relaxed);
        let name = format!("sme-valkey-test-{}-{seq}", std::process::id());
        let appendonly = if ephemeral { "no" } else { "yes" };

        let output = Command::new("docker")
            .args([
                "run", "-d", "--rm", "--name", &name, "--tmpfs", "/data", "-p",
            ])
            .arg(format!("127.0.0.1:{port}:6379"))
            .args([
                "valkey/valkey:9.1.2-alpine",
                "valkey-server",
                "--save",
                "",
                "--appendonly",
                appendonly,
                "--dir",
                "/data",
                "--maxmemory",
                "64mb",
                "--maxmemory-policy",
                "noeviction",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("无法启动 docker：{error}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker run 失败：{}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let container = Self {
            name,
            url: format!("redis://127.0.0.1:{port}"),
            port,
        };
        container.wait_ready().await?;
        Ok(container)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 重启容器（模拟 Valkey 进程重启；用来验证 I8）。
    pub async fn restart(&self) -> Result<(), String> {
        let status = Command::new("docker")
            .args(["restart", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|error| format!("docker restart 失败：{error}"))?;
        if !status.success() {
            return Err(format!("docker restart {} 返回 {status}", self.name));
        }
        self.wait_ready().await
    }

    pub async fn wait_ready(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match ping(&self.url).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(format!("Valkey 未就绪：{error}"));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// 读取容器日志，I7 负例里用来断言网关确实拒绝启动。
    pub fn logs(&self) -> Result<String, String> {
        let output = Command::new("docker")
            .args(["logs", &self.name])
            .output()
            .map_err(|error| format!("docker logs 失败：{error}"))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr))
    }
}

impl Drop for ValkeyContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn ping(url: &str) -> Result<(), String> {
    let client = redis::Client::open(url).map_err(|error| error.to_string())?;
    let mut connection = client
        .get_connection_manager()
        .await
        .map_err(|error| error.to_string())?;
    redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// 让操作系统分配一个空闲端口（存在极小竞态，测试里可接受）。
pub fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("无法分配空闲端口：{error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| format!("无法读取本地端口：{error}"))
}

/// 自清理的临时目录。
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sme-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 最小 WS 测试客户端。
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn connect(url: &str) -> Socket {
    let (socket, _) = connect_async(url).await.expect("connect websocket");
    socket
}

/// 连接失败时返回 `None`，用于等待服务端就绪。
pub async fn try_connect(url: &str) -> Option<Socket> {
    connect_async(url).await.ok().map(|(socket, _)| socket)
}

pub async fn send_frame(socket: &mut Socket, frame: &Frame) {
    socket
        .send(Message::Binary(encode(frame).unwrap().into()))
        .await
        .unwrap();
}

pub async fn recv_frame(socket: &mut Socket) -> Frame {
    loop {
        match socket
            .next()
            .await
            .expect("socket open")
            .expect("socket ok")
        {
            Message::Binary(bytes) => return decode(&bytes).unwrap(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("unexpected websocket message: {other:?}"),
        }
    }
}

pub async fn register(socket: &mut Socket, id: AccountId, account: &Account) {
    let identity = account.identity_keys();
    send_frame(
        socket,
        &Frame::Register(sme_proto::Registration {
            account_id: id,
            ed25519_pub: *identity.ed25519.as_bytes(),
            curve25519_pub: *identity.curve25519.as_bytes(),
            kdf_salt: [1u8; 16],
            kdf_params: sme_proto::KdfParams {
                m_cost: 19_456,
                t_cost: 2,
                p_cost: 1,
            },
        }),
    )
    .await;

    match recv_frame(socket).await {
        Frame::RegisterAck { account_id } => assert_eq!(account_id, id),
        other => panic!("expected RegisterAck, got {other:?}"),
    }
}

pub async fn login(socket: &mut Socket, id: AccountId, account: &Account) {
    send_frame(socket, &Frame::ChallengeRequest { account_id: id }).await;
    let Frame::Challenge { nonce } = recv_frame(socket).await else {
        panic!("expected Challenge");
    };

    let signature = account.sign(login_payload(&id, &nonce));
    send_frame(
        socket,
        &Frame::Login {
            account_id: id,
            nonce,
            signature: Signature::from_bytes(signature.to_bytes()),
        },
    )
    .await;

    match recv_frame(socket).await {
        Frame::LoginAck { account_id } => assert_eq!(account_id, id),
        other => panic!("expected LoginAck, got {other:?}"),
    }
}
