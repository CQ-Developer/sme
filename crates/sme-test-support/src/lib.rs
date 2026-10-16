//! Integration-test support: temporary Valkey containers, temp directories and a minimal WS client.
//!
//! Used only by `sme-server` / `sme-client-tui` tests; never linked into a product binary.

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

/// A Valkey container started by a test and removed when the process exits.
pub struct ValkeyContainer {
    name: String,
    url: String,
    port: u16,
}

impl ValkeyContainer {
    /// Start a persistence-disabled Valkey (tmpfs + `--save ""` + `--appendonly no`).
    pub async fn ephemeral() -> Result<Self, String> {
        Self::start_with(true).await
    }

    /// A Valkey with AOF deliberately enabled, for the I7 negative case.
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
            .map_err(|error| format!("cannot start docker: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker run failed: {}",
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

    /// Restart the container (simulates a Valkey process restart; verifies I8).
    pub async fn restart(&self) -> Result<(), String> {
        let status = Command::new("docker")
            .args(["restart", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|error| format!("docker restart failed: {error}"))?;
        if !status.success() {
            return Err(format!("docker restart {} returned {status}", self.name));
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
                        return Err(format!("Valkey is not ready: {error}"));
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    /// Read container logs; the I7 negative case uses this to assert the gateway really refused to start.
    pub fn logs(&self) -> Result<String, String> {
        let output = Command::new("docker")
            .args(["logs", &self.name])
            .output()
            .map_err(|error| format!("docker logs failed: {error}"))?;
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

/// Ask the OS for a free port (a tiny race, acceptable in tests).
pub fn free_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|error| format!("cannot allocate a free port: {error}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|error| format!("cannot read the local port: {error}"))
}

/// Self-cleaning temp directory.
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

/// Minimal WS test client.
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn connect(url: &str) -> Socket {
    let (socket, _) = connect_async(url).await.expect("connect websocket");
    socket
}

/// Returns `None` on connect failure, used to wait for the server to become ready.
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
