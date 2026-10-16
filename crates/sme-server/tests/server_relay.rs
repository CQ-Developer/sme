//! M2/M3 服务端集成测试：注册 → 登录 → 预密钥 → 密文转发 → D-ack。
//!
//! 需要真实 Postgres（`DATABASE_URL`）与 Docker（临时 Valkey 容器）；
//! 缺少任一条件时打印提示并跳过。

use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, OlmMessageKind, PROTOCOL_VERSION, PreKeyUpload,
    Signature, login_payload,
};
use sme_server::valkey::{Valkey, random_instance_id};
use sme_server::{app, state::AppState};
use sme_test_support::{ValkeyContainer, connect, login, recv_frame, register, send_frame};
use sqlx::postgres::PgPoolOptions;
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{
    Account, Message as OlmNormalMessage, OlmMessage, PreKeyMessage, SessionConfig,
};

const HMAC_KEY: &[u8] = b"test-hmac-key-0123456789abcdef";

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// 起一个绑定随机端口的网关；返回 URL 与必须保活的 Valkey 容器句柄。
async fn test_server() -> Option<(String, ValkeyContainer)> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let container = match ValkeyContainer::ephemeral().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("跳过服务端集成测试：无法启动 Valkey 容器（{error}）");
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

#[tokio::test]
async fn relay_delivers_only_ciphertext() {
    let Some((url, _valkey)) = test_server().await else {
        eprintln!("跳过服务端集成测试：未设置 DATABASE_URL");
        return;
    };

    let alice_id = AccountId::random();
    let bob_id = AccountId::random();
    let alice = Account::new();
    let mut bob = Account::new();

    let mut alice_socket = connect(&url).await;
    let mut bob_socket = connect(&url).await;
    register(&mut alice_socket, alice_id, &alice).await;
    register(&mut bob_socket, bob_id, &bob).await;
    login(&mut alice_socket, alice_id, &alice).await;
    login(&mut bob_socket, bob_id, &bob).await;

    // Bob 上传一次性预密钥。
    bob.generate_one_time_keys(1);
    let (key_id, one_time_key) = bob
        .one_time_keys()
        .into_iter()
        .next()
        .expect("one-time key");
    send_frame(
        &mut bob_socket,
        &Frame::UploadPreKeys {
            prekeys: vec![PreKeyUpload {
                key_id: key_id.to_base64(),
                public_key: *one_time_key.as_bytes(),
            }],
        },
    )
    .await;
    match recv_frame(&mut bob_socket).await {
        Frame::UploadPreKeysAck { stored } => assert_eq!(stored, 1),
        other => panic!("expected UploadPreKeysAck, got {other:?}"),
    }
    bob.mark_keys_as_published();

    // Alice 取回 bundle 并建立 Olm 会话。
    send_frame(
        &mut alice_socket,
        &Frame::FetchPreKey { account_id: bob_id },
    )
    .await;
    let Frame::PreKeyBundle(bundle) = recv_frame(&mut alice_socket).await else {
        panic!("expected PreKeyBundle");
    };
    assert_eq!(bundle.account_id, bob_id);

    let mut alice_session = alice
        .create_outbound_session(
            SessionConfig::default(),
            Curve25519PublicKey::from_bytes(bundle.curve25519_pub),
            Curve25519PublicKey::from_bytes(bundle.one_time_key),
        )
        .unwrap();

    let plaintext = b"sme canary: server must only ever see ciphertext";
    let message = match alice_session.encrypt(plaintext).unwrap() {
        OlmMessage::PreKey(message) => message,
        OlmMessage::Normal(_) => panic!("first message must be a pre-key message"),
    };
    let envelope = Envelope {
        v: PROTOCOL_VERSION,
        from: alice_id,
        to: bob_id,
        sid: alice_session.session_id(),
        kind: OlmMessageKind::PreKey,
        payload: message.to_bytes(),
    };

    send_frame(&mut alice_socket, &Frame::Send(envelope)).await;
    let Frame::SendAck { msg_id } = recv_frame(&mut alice_socket).await else {
        panic!("expected SendAck");
    };

    // 收件人拿到的必须只有密文。
    let Frame::Deliver {
        msg_id: delivered_id,
        envelope: delivered,
    } = recv_frame(&mut bob_socket).await
    else {
        panic!("expected Deliver");
    };
    assert_eq!(delivered_id, msg_id);
    assert_eq!(delivered.from, alice_id);
    assert_eq!(delivered.kind, OlmMessageKind::PreKey);
    assert!(
        !delivered
            .payload
            .windows(plaintext.len())
            .any(|window| window == plaintext),
        "服务端不得让明文出现在线路上"
    );

    // Bob 用 pre-key 消息建立入站会话并解出明文。
    let pre_key_message = PreKeyMessage::from_bytes(&delivered.payload).unwrap();
    let inbound = bob
        .create_inbound_session(
            SessionConfig::default(),
            alice.identity_keys().curve25519,
            &pre_key_message,
        )
        .unwrap();
    assert_eq!(inbound.plaintext, plaintext.to_vec());
    let mut bob_session = inbound.session;

    send_frame(&mut bob_socket, &Frame::DeliverAck { msg_id }).await;

    // 反向：Bob 回一条 Normal 消息，Alice 必须能解开。
    let reply = match bob_session.encrypt("reply from bob").unwrap() {
        OlmMessage::Normal(message) => message,
        OlmMessage::PreKey(_) => panic!("session is established, expected normal message"),
    };
    let reply_envelope = Envelope {
        v: PROTOCOL_VERSION,
        from: bob_id,
        to: alice_id,
        sid: bob_session.session_id(),
        kind: OlmMessageKind::Normal,
        payload: reply.to_bytes(),
    };

    send_frame(&mut bob_socket, &Frame::Send(reply_envelope)).await;
    let Frame::SendAck { msg_id: reply_id } = recv_frame(&mut bob_socket).await else {
        panic!("expected SendAck");
    };
    let Frame::Deliver {
        msg_id: delivered_reply_id,
        envelope: delivered_reply,
    } = recv_frame(&mut alice_socket).await
    else {
        panic!("expected Deliver");
    };
    assert_eq!(delivered_reply_id, reply_id);

    let normal = OlmNormalMessage::from_bytes(&delivered_reply.payload).unwrap();
    let decrypted = alice_session.decrypt(&OlmMessage::Normal(normal)).unwrap();
    assert_eq!(decrypted, b"reply from bob".to_vec());
}

#[tokio::test]
async fn login_rejects_a_bad_signature() {
    let Some((url, _valkey)) = test_server().await else {
        eprintln!("跳过服务端集成测试：未设置 DATABASE_URL");
        return;
    };

    let victim = Account::new();
    let victim_id = AccountId::random();
    let mallory = Account::new();

    let mut socket = connect(&url).await;
    register(&mut socket, victim_id, &victim).await;

    // Mallory 用自己的密钥签 Victim 的挑战。
    send_frame(
        &mut socket,
        &Frame::ChallengeRequest {
            account_id: victim_id,
        },
    )
    .await;
    let Frame::Challenge { nonce } = recv_frame(&mut socket).await else {
        panic!("expected Challenge");
    };
    let forged = mallory.sign(login_payload(&victim_id, &nonce));
    send_frame(
        &mut socket,
        &Frame::Login {
            account_id: victim_id,
            nonce,
            signature: Signature::from_bytes(forged.to_bytes()),
        },
    )
    .await;

    match recv_frame(&mut socket).await {
        Frame::Error {
            code: ErrorCode::BadSignature,
            ..
        } => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[tokio::test]
async fn a_new_login_kicks_the_previous_connection() {
    let Some((url, _valkey)) = test_server().await else {
        eprintln!("跳过服务端集成测试：未设置 DATABASE_URL");
        return;
    };

    let account = Account::new();
    let account_id = AccountId::random();

    let mut first = connect(&url).await;
    register(&mut first, account_id, &account).await;
    login(&mut first, account_id, &account).await;

    let mut second = connect(&url).await;
    login(&mut second, account_id, &account).await;

    match recv_frame(&mut first).await {
        Frame::Error {
            code: ErrorCode::SessionReplaced,
            ..
        } => {}
        other => panic!("expected SessionReplaced, got {other:?}"),
    }
}
