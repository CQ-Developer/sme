//! M2 端到端测试：真实网关 + 两个客户端 + 会话跨重启恢复。
//!
//! 断言：注册/登录、预密钥握手、双向收发、离线队列、D-ack、
//! 以及「线上只有密文」和「重启后棘轮继续可用」。
//!
//! 需要真实 Postgres（`DATABASE_URL`）；未设置时跳过。

use sme_client_core::{Action, Client};
use sme_client_net::Transport;
use sme_client_store::Keystore;
use sme_proto::{AccountId, Envelope, Frame, KdfParams};
use sme_server::valkey::{Valkey, random_instance_id};
use sme_server::{app, state::AppState};
use sme_test_support::{TestDir, ValkeyContainer};
use sqlx::postgres::PgPoolOptions;
use vodozemac::olm::Account;

const PASSWORD: &[u8] = b"correct horse battery staple";
const KDF_SALT: [u8; 16] = [3u8; 16];
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

/// `Action::Persist` 的落点：账号 + 全部会话。
fn persist(client: &Client, store: &mut Keystore) {
    store.save_account(client.account()).unwrap();
    for (peer, session) in client.sessions() {
        store.save_session(peer, session).unwrap();
    }
    store.save().unwrap();
}

async fn run_actions(
    client: &Client,
    transport: &mut Transport,
    store: &mut Keystore,
    actions: Vec<Action>,
) -> Vec<Action> {
    let mut events = Vec::new();
    for action in actions {
        match action {
            Action::Send(frame) => transport.send(&frame).await.unwrap(),
            Action::Persist => persist(client, store),
            other => events.push(other),
        }
    }
    events
}

/// 处理服务端帧，直到 `done` 命中一个事件。
async fn drive_until(
    client: &mut Client,
    transport: &mut Transport,
    store: &mut Keystore,
    done: impl Fn(&Action) -> bool,
) -> Vec<Action> {
    let mut events = Vec::new();
    loop {
        let frame = transport
            .recv()
            .await
            .unwrap()
            .expect("server closed the connection");
        let actions = client.handle_frame(frame);
        let mut finished = false;
        for action in actions {
            match action {
                Action::Send(frame) => transport.send(&frame).await.unwrap(),
                Action::Persist => persist(client, store),
                other => {
                    if done(&other) {
                        finished = true;
                    }
                    events.push(other);
                }
            }
        }
        if finished {
            return events;
        }
    }
}

async fn register_and_login(client: &mut Client, transport: &mut Transport, store: &mut Keystore) {
    let actions = client.registration(
        KDF_SALT,
        KdfParams {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        },
    );
    run_actions(client, transport, store, actions).await;
    let events = drive_until(client, transport, store, |action| {
        matches!(action, Action::Registered)
    })
    .await;
    assert!(
        events
            .iter()
            .any(|action| matches!(action, Action::Registered))
    );

    let actions = client.challenge_request();
    run_actions(client, transport, store, actions).await;
    let events = drive_until(client, transport, store, |action| {
        matches!(action, Action::Ready)
    })
    .await;
    assert!(events.iter().any(|action| matches!(action, Action::Ready)));
}

/// 取出待发信封，并断言明文没有出现在线路上（服务端只见密文）。
fn outgoing_envelope(actions: &[Action], plaintext: &[u8]) -> Envelope {
    let envelope = actions
        .iter()
        .find_map(|action| match action {
            Action::Send(Frame::Send(envelope)) => Some(envelope.clone()),
            _ => None,
        })
        .expect("expected a Send frame");
    assert!(
        !envelope
            .payload
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "明文不得出现在线路上"
    );
    envelope
}

#[tokio::test]
async fn two_clients_chat_and_resume_after_restart() {
    let Some((url, _valkey)) = start_server().await else {
        eprintln!("跳过端到端测试：未设置 DATABASE_URL");
        return;
    };

    let dir = TestDir::new("e2e");
    let alice_id = AccountId::random();
    let bob_id = AccountId::random();

    // ---- Alice 注册并登录 ----
    let alice_path = dir.join("alice.bin");
    let mut alice_store = Keystore::create(&alice_path, PASSWORD).unwrap();
    let mut alice = Client::new(alice_id, Account::new());
    let mut alice_transport = Transport::connect(&url).await.unwrap();
    register_and_login(&mut alice, &mut alice_transport, &mut alice_store).await;
    persist(&alice, &mut alice_store);

    // ---- Bob 注册、登录并上传预密钥 ----
    let bob_path = dir.join("bob.bin");
    let mut bob_store = Keystore::create(&bob_path, PASSWORD).unwrap();
    let mut bob = Client::new(bob_id, Account::new());
    let mut bob_transport = Transport::connect(&url).await.unwrap();
    register_and_login(&mut bob, &mut bob_transport, &mut bob_store).await;

    let actions = bob.prekey_upload(5);
    run_actions(&bob, &mut bob_transport, &mut bob_store, actions).await;
    let events = drive_until(&mut bob, &mut bob_transport, &mut bob_store, |action| {
        matches!(action, Action::PreKeysUploaded { .. })
    })
    .await;
    assert!(
        events
            .iter()
            .any(|action| matches!(action, Action::PreKeysUploaded { stored: 5 }))
    );

    // ---- Alice 取预密钥、建立 Olm 会话 ----
    let actions = alice.fetch_prekey(bob_id);
    run_actions(&alice, &mut alice_transport, &mut alice_store, actions).await;
    let events = drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::SessionEstablished { .. }),
    )
    .await;
    assert!(
        events
            .iter()
            .any(|action| matches!(action, Action::SessionEstablished { peer } if *peer == bob_id))
    );

    // ---- Alice → Bob ----
    let plaintext = b"CANARY-e2e-7f3a: hello bob over the wire";
    let actions = alice.send_text(bob_id, plaintext).unwrap();
    outgoing_envelope(&actions, plaintext);
    run_actions(&alice, &mut alice_transport, &mut alice_store, actions).await;
    drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::Sent { .. }),
    )
    .await;

    drive_until(&mut bob, &mut bob_transport, &mut bob_store, |action| {
        matches!(action, Action::Received { .. })
    })
    .await;
    assert_eq!(bob.buffer().newest().unwrap().plaintext, plaintext.to_vec());

    // ---- Bob → Alice ----
    let actions = bob.send_text(alice_id, b"reply from bob").unwrap();
    run_actions(&bob, &mut bob_transport, &mut bob_store, actions).await;
    drive_until(&mut bob, &mut bob_transport, &mut bob_store, |action| {
        matches!(action, Action::Sent { .. })
    })
    .await;
    drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::Received { .. }),
    )
    .await;
    assert_eq!(
        alice.buffer().newest().unwrap().plaintext,
        b"reply from bob".to_vec()
    );

    persist(&alice, &mut alice_store);
    persist(&bob, &mut bob_store);

    // ---- Alice 掉线；Bob 继续发，消息应进服务端队列 ----
    drop(alice);
    drop(alice_transport);
    drop(alice_store);

    let offline_plaintext = b"CANARY-e2e-7f3a: while you were away";
    let actions = bob.send_text(alice_id, offline_plaintext).unwrap();
    outgoing_envelope(&actions, offline_plaintext);
    run_actions(&bob, &mut bob_transport, &mut bob_store, actions).await;
    drive_until(&mut bob, &mut bob_transport, &mut bob_store, |action| {
        matches!(action, Action::Sent { .. })
    })
    .await;

    // ---- Alice 从 keystore 重启，会话必须恢复 ----
    let mut alice_store = Keystore::open(&alice_path, PASSWORD).unwrap();
    let alice_account = alice_store
        .load_account()
        .unwrap()
        .expect("account restored");
    let sessions = alice_store.load_sessions().unwrap();
    assert_eq!(sessions.len(), 1, "会话必须在 keystore 里");
    let mut alice = Client::restore(alice_id, alice_account, sessions);
    let mut alice_transport = Transport::connect(&url).await.unwrap();
    run_actions(
        &alice,
        &mut alice_transport,
        &mut alice_store,
        alice.challenge_request(),
    )
    .await;
    drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::Ready),
    )
    .await;

    // 登录后服务端投递离线消息，恢复后的棘轮必须能解开。
    let events = drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::Received { .. }),
    )
    .await;
    assert!(events.iter().any(
        |action| matches!(action, Action::Received { plaintext, .. } if plaintext == offline_plaintext)
    ));
    assert_eq!(
        alice.buffer().newest().unwrap().plaintext,
        offline_plaintext.to_vec()
    );

    // ---- 恢复后的 Alice 继续发 ----
    let actions = alice
        .send_text(bob_id, b"still here after restart")
        .unwrap();
    run_actions(&alice, &mut alice_transport, &mut alice_store, actions).await;
    drive_until(
        &mut alice,
        &mut alice_transport,
        &mut alice_store,
        |action| matches!(action, Action::Sent { .. }),
    )
    .await;
    drive_until(&mut bob, &mut bob_transport, &mut bob_store, |action| {
        matches!(action, Action::Received { plaintext, .. } if plaintext == b"still here after restart")
    })
    .await;
}
