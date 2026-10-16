//! M2/M4 端到端测试（走 TUI 的 [`Session`] 层）：真实网关 + 两个客户端。
//!
//! 断言：注册/登录、预密钥握手、双向收发、离线队列、D-ack、跨重启恢复，
//! 以及 **I4**：应用目录里不得出现任何明文消息。
//!
//! 需要真实 Postgres（`DATABASE_URL`）与 Docker（临时 Valkey 容器）。

use std::path::Path;

use sme_client_tui::session::{Event, Session};
use sme_server::valkey::{Valkey, random_instance_id};
use sme_server::{app, state::AppState};
use sme_test_support::{TestDir, ValkeyContainer};
use sqlx::postgres::PgPoolOptions;

const PASSWORD: &[u8] = b"correct horse battery staple";
const HMAC_KEY: &[u8] = b"test-hmac-key-0123456789abcdef";

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// 起一个绑定随机端口的网关；返回 URL 与必须保活的 Valkey 容器句柄。
async fn start_server() -> Option<(String, ValkeyContainer)> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let container = match ValkeyContainer::ephemeral().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("跳过端到端测试：无法启动 Valkey 容器（{error}）");
            return None;
        }
    };

    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .expect("connect test database");
    MIGRATED
        .get_or_init(|| async {
            sqlx::migrate!("../../migrations")
                .run(&pool)
                .await
                .expect("run migrations");
        })
        .await;

    let valkey = Valkey::connect(
        container.url(),
        HMAC_KEY,
        random_instance_id().expect("instance id"),
    )
    .await
    .expect("connect valkey");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(AppState::new(pool, valkey)))
            .await
            .unwrap();
    });

    Some((format!("ws://{addr}/ws"), container))
}

async fn next_until(session: &mut Session, wanted: impl Fn(&Event) -> bool) -> Event {
    loop {
        let event = session.next_event().await.expect("session event");
        if wanted(&event) {
            return event;
        }
    }
}

/// I4：递归扫描目录，任何文件里都不得出现明文。
fn assert_no_plaintext(dir: &Path, plaintext: &[u8]) {
    for entry in std::fs::read_dir(dir).expect("read app dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            assert_no_plaintext(&path, plaintext);
        } else {
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(
                !bytes
                    .windows(plaintext.len())
                    .any(|window| window == plaintext),
                "{} 里出现了明文消息",
                path.display()
            );
        }
    }
}

#[tokio::test]
async fn two_clients_chat_and_resume_after_restart() {
    let Some((url, _valkey)) = start_server().await else {
        eprintln!("跳过端到端测试：未设置 DATABASE_URL");
        return;
    };

    let dir = TestDir::new("e2e");
    let alice_path = dir.join("alice.bin");
    let bob_path = dir.join("bob.bin");

    let mut alice = Session::connect(&url, &alice_path, PASSWORD)
        .await
        .expect("alice connects");
    let alice_id = alice.account_id();
    let mut bob = Session::connect(&url, &bob_path, PASSWORD)
        .await
        .expect("bob connects");
    let bob_id = bob.account_id();

    // 握手：Bob 上传预密钥，Alice 取回并建立会话。
    bob.upload_prekeys(5).await.unwrap();
    next_until(&mut bob, |event| {
        matches!(event, Event::PreKeysUploaded { .. })
    })
    .await;
    alice.fetch_prekey(bob_id).await.unwrap();
    next_until(&mut alice, |event| {
        matches!(event, Event::SessionEstablished { .. })
    })
    .await;

    // ---- Alice → Bob ----
    let plaintext = "CANARY-e2e-7f3a: hello bob over the wire";
    alice.send_text(bob_id, plaintext.as_bytes()).await.unwrap();
    let Event::Received { text, .. } =
        next_until(&mut bob, |event| matches!(event, Event::Received { .. })).await
    else {
        panic!("expected Received");
    };
    assert_eq!(text, plaintext);

    // ---- Bob → Alice ----
    bob.send_text(alice_id, b"reply from bob").await.unwrap();
    next_until(
        &mut alice,
        |event| matches!(event, Event::Received { text, .. } if text == "reply from bob"),
    )
    .await;

    // ---- Alice 掉线；Bob 的消息进服务端队列 ----
    let offline = "CANARY-e2e-7f3a: while you were away";
    drop(alice);
    bob.send_text(alice_id, offline.as_bytes()).await.unwrap();

    // ---- Alice 从 keystore 重启，恢复会话并取回离线消息 ----
    let mut alice = Session::connect(&url, &alice_path, PASSWORD)
        .await
        .expect("alice reconnects");
    let Event::Received { text, .. } =
        next_until(&mut alice, |event| matches!(event, Event::Received { .. })).await
    else {
        panic!("expected offline message");
    };
    assert_eq!(text, offline);

    // ---- 恢复后的 Alice 继续发 ----
    alice
        .send_text(bob_id, b"still here after restart")
        .await
        .unwrap();
    next_until(
        &mut bob,
        |event| matches!(event, Event::Received { text, .. } if text == "still here after restart"),
    )
    .await;

    // ---- I4：应用自己的目录里不得有任何明文 ----
    assert_no_plaintext(dir.path(), plaintext.as_bytes());
    assert_no_plaintext(dir.path(), offline.as_bytes());
    assert_no_plaintext(dir.path(), b"reply from bob");

    // ---- I6 语义：紧急擦除后内存缓冲为空 ----
    alice.wipe_memory();
    assert!(alice.messages().is_empty());
}

#[tokio::test]
async fn emergency_wipe_deletes_local_state() {
    let Some((url, _valkey)) = start_server().await else {
        eprintln!("跳过端到端测试：未设置 DATABASE_URL");
        return;
    };

    let dir = TestDir::new("wipe");
    let path = dir.join("carol.bin");
    let mut carol = Session::connect(&url, &path, PASSWORD)
        .await
        .expect("carol connects");

    assert!(path.exists());
    let config_path = sme_client_store::LocalConfig::path_for(&path);
    assert!(config_path.exists());

    carol.wipe_memory();
    carol.delete_keystore().expect("delete keystore");

    assert!(!path.exists());
    assert!(!config_path.exists());
}
