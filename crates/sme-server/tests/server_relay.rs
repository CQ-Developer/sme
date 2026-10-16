//! M2/M3 server integration test: register -> login -> prekeys -> ciphertext relay -> D-ack.
//!
//! Requires real Postgres (`DATABASE_URL`) and Docker (temporary Valkey containers);
//! Prints a note and skips when either dependency is missing.

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

/// Start a gateway on a random port; returns the URL and a Valkey container handle that must stay alive.
async fn test_server() -> Option<(String, ValkeyContainer)> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let container = match ValkeyContainer::ephemeral().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("skipping server integration test: cannot start Valkey container ({error})");
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
        eprintln!("skipping server integration test: DATABASE_URL is not set");
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

    // Bob uploads one-time prekeys.
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

    // Alice fetches the bundle and establishes an Olm session.
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

    // The recipient must receive ciphertext only.
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
        "the server must never put plaintext on the wire"
    );

    // Bob builds the inbound session from the pre-key message and decrypts it.
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

    // Reverse direction: Bob replies with a normal message and Alice must decrypt it.
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
        eprintln!("skipping server integration test: DATABASE_URL is not set");
        return;
    };

    let victim = Account::new();
    let victim_id = AccountId::random();
    let mallory = Account::new();

    let mut socket = connect(&url).await;
    register(&mut socket, victim_id, &victim).await;

    // Mallory signs Victim's challenge with her own key.
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
        eprintln!("skipping server integration test: DATABASE_URL is not set");
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
