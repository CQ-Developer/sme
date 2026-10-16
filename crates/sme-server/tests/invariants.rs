//! M3 invariant tests: I1 (no message columns in the schema), I5 (no ciphertext in logs),
//! I7 (startup self-check refuses persistence) and I8 (no ciphertext survives a Valkey restart).
//!
//! Requires real Postgres (`DATABASE_URL`) and Docker; skips when either is missing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sme_proto::{AccountId, Envelope, Frame, OlmMessageKind, PROTOCOL_VERSION, encode_envelope};
use sme_server::valkey::{Valkey, ValkeyError};
use sme_test_support::{
    TestDir, ValkeyContainer, connect, free_port, recv_frame, register, send_frame, try_connect,
};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use vodozemac::olm::Account;

const HMAC_KEY: &[u8] = b"test-hmac-key-0123456789abcdef";

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

async fn test_pool() -> Option<sqlx::PgPool> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
    Some(pool)
}

/// I1: the persistent layer has no message table or column.
#[tokio::test]
async fn i1_persistent_schema_has_no_message_columns() {
    let Some(pool) = test_pool().await else {
        eprintln!("跳过 I1：未设置 DATABASE_URL");
        return;
    };

    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_schema, table_name FROM information_schema.tables
         WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
         ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("list tables");
    let names: Vec<&str> = tables.iter().map(|(_, name)| name.as_str()).collect();
    assert_eq!(
        names,
        vec!["_sqlx_migrations", "accounts"],
        "持久层只允许 accounts 与 sqlx 迁移表"
    );

    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = 'public'
         ORDER BY table_name, column_name",
    )
    .fetch_all(&pool)
    .await
    .expect("list columns");

    const FORBIDDEN: [&str; 6] = [
        "message",
        "content",
        "body",
        "payload",
        "ciphertext",
        "envelope",
    ];
    for (table, column) in columns {
        let column = column.to_lowercase();
        for word in FORBIDDEN {
            assert!(
                !column.contains(word),
                "列 {table}.{column} 命中禁词 {word}"
            );
        }
    }
}

/// I5: run a unique canary through the envelope payload's whole lifecycle and assert it never reaches server output.
#[tokio::test]
async fn i5_server_logs_never_contain_ciphertext_payload() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        eprintln!("跳过 I5：未设置 DATABASE_URL");
        return;
    };
    let valkey = match ValkeyContainer::ephemeral().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("跳过 I5：无法启动 Valkey 容器（{error}）");
            return;
        }
    };
    let port = free_port().expect("free port");
    let _dir = TestDir::new("i5");

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_sme-server"))
        .env("DATABASE_URL", &database_url)
        .env("VALKEY_URL", valkey.url())
        .env(
            "SME_HMAC_KEY",
            String::from_utf8_lossy(HMAC_KEY).to_string(),
        )
        .env("SME_BIND_ADDR", format!("127.0.0.1:{port}"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sme-server");

    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let logs = Arc::new(Mutex::new(String::new()));
    let stdout_task = tokio::spawn(collect_lines(stdout, logs.clone()));
    let stderr_task = tokio::spawn(collect_lines(stderr, logs.clone()));

    let url = format!("ws://127.0.0.1:{port}/ws");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut alice_socket = loop {
        if let Some(socket) = try_connect(&url).await {
            break socket;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sme-server 未在超时内启动"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let alice_id = AccountId::random();
    let bob_id = AccountId::random();
    let alice = Account::new();
    let bob = Account::new();
    let mut bob_socket = connect(&url).await;
    register(&mut alice_socket, alice_id, &alice).await;
    register(&mut bob_socket, bob_id, &bob).await;
    sme_test_support::login(&mut alice_socket, alice_id, &alice).await;
    sme_test_support::login(&mut bob_socket, bob_id, &bob).await;

    let canary = "CANARY-I5-9f2b7c: this must never appear in server logs";
    let envelope = Envelope {
        v: PROTOCOL_VERSION,
        from: alice_id,
        to: bob_id,
        sid: "canary-session".to_string(),
        kind: OlmMessageKind::Normal,
        payload: canary.as_bytes().to_vec(),
    };
    send_frame(&mut alice_socket, &Frame::Send(envelope)).await;
    let Frame::SendAck { msg_id } = recv_frame(&mut alice_socket).await else {
        panic!("expected SendAck");
    };
    let Frame::Deliver {
        envelope: delivered,
        ..
    } = recv_frame(&mut bob_socket).await
    else {
        panic!("expected Deliver");
    };
    assert_eq!(delivered.payload, canary.as_bytes().to_vec());
    send_frame(&mut bob_socket, &Frame::DeliverAck { msg_id }).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    child.kill().await.expect("kill server");
    let _ = child.wait().await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    let logs = logs.lock().unwrap().clone();
    assert!(
        !logs.contains(canary),
        "服务端输出流里出现了消息内容：\n{logs}"
    );
}

async fn collect_lines<R: AsyncRead + Unpin>(reader: R, logs: Arc<Mutex<String>>) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut logs = logs.lock().unwrap();
        logs.push_str(&line);
        logs.push('\n');
    }
}

/// I7: `Valkey::connect` must refuse persistence-enabled Valkey and accept it when disabled.
#[tokio::test]
async fn i7_startup_refuses_persistent_valkey() {
    let persistent = match ValkeyContainer::with_appendonly().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("跳过 I7：无法启动 Valkey 容器（{error}）");
            return;
        }
    };
    let result = Valkey::connect(persistent.url(), HMAC_KEY, "i7-test".to_string()).await;
    assert!(
        matches!(result, Err(ValkeyError::NotEphemeral(_))),
        "appendonly=yes 的 Valkey 必须被拒绝"
    );

    let ephemeral = ValkeyContainer::ephemeral().await.expect("start valkey");
    assert!(
        Valkey::connect(ephemeral.url(), HMAC_KEY, "i7-test".to_string())
            .await
            .is_ok()
    );
}

/// I8: enqueue ciphertext -> restart Valkey -> the queue is empty.
#[tokio::test]
async fn i8_restart_leaves_no_ciphertext() {
    let container = match ValkeyContainer::ephemeral().await {
        Ok(container) => container,
        Err(error) => {
            eprintln!("跳过 I8：无法启动 Valkey 容器（{error}）");
            return;
        }
    };
    let url = container.url().to_string();
    let valkey = Valkey::connect(&url, HMAC_KEY, "i8-test".to_string())
        .await
        .expect("connect valkey");

    let account = AccountId::random();
    let envelope = Envelope {
        v: PROTOCOL_VERSION,
        from: AccountId::random(),
        to: account,
        sid: "sid-i8".to_string(),
        kind: OlmMessageKind::Normal,
        payload: vec![7u8; 64],
    };
    let bytes = encode_envelope(&envelope).unwrap();

    let entry_id = valkey.enqueue(account, &bytes).await.unwrap();
    assert!(!entry_id.is_empty());
    assert_eq!(valkey.queued(account).await.unwrap().len(), 1);

    // D-ack deletes immediately (also exercises the ack script).
    valkey.ack(account, &entry_id).await.unwrap();
    assert!(valkey.queued(account).await.unwrap().is_empty());

    // Enqueue one more; it must be gone after the restart.
    valkey.enqueue(account, &bytes).await.unwrap();
    drop(valkey);

    container.restart().await.expect("restart valkey");
    let valkey = Valkey::connect(&url, HMAC_KEY, "i8-test".to_string())
        .await
        .expect("reconnect valkey");
    assert!(
        valkey.queued(account).await.unwrap().is_empty(),
        "Valkey 重启后不得残留任何密文"
    );
}
