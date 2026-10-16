//! WebSocket 状态机：注册 → 挑战-签名登录 → 预密钥 / 密文转发（M3）。
//!
//! 网关无状态：队列、预密钥、挑战与 presence 全在 Valkey；本进程只保存活连接。
//! 帧的 `payload` 不解析、不落日志；所有错误都以 `Frame::Error` 回给对端。

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use sme_proto::{
    AccountId, ErrorCode, Frame, PreKeyBundle, decode, encode, encode_envelope, login_payload,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::db;
use crate::state::{
    AppState, BIG_MESSAGE_BYTES, CHALLENGE_RATE_LIMIT_PER_MINUTE, Connection,
    MESSAGE_RATE_LIMIT_PER_MINUTE,
};

/// 写方向缓冲深度：够了就行，避免慢客户端吃内存。
const WRITE_QUEUE: usize = 128;

/// presence 心跳间隔（docs/INFRA.md §4.1：20s 续期，TTL 60s）。
const PRESENCE_REFRESH_INTERVAL: Duration = Duration::from_secs(20);

/// 每账号每分钟的消息限流窗口。
const RATE_WINDOW_SECS: u64 = 60;

pub async fn ws_handler(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| async move {
        handle_socket(state, socket).await;
    })
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Frame>(WRITE_QUEUE);
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let Ok(bytes) = encode(&frame) else {
                eprintln!("dropping outbound frame that failed to encode");
                continue;
            };
            if sink.send(Message::Binary(bytes.into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let conn_id = state.next_connection_id();
    let mut account: Option<AccountId> = None;
    let mut pubsub_task: Option<JoinHandle<()>> = None;
    let mut presence_task: Option<JoinHandle<()>> = None;

    loop {
        tokio::select! {
            message = stream.next() => {
                let Some(message) = message else { break };
                let Ok(message) = message else { break };
                if let Message::Binary(bytes) = message {
                    match decode(&bytes) {
                        Ok(frame) => {
                            handle_frame(
                                &state,
                                &mut account,
                                conn_id,
                                &tx,
                                &kick_tx,
                                &mut pubsub_task,
                                &mut presence_task,
                                frame,
                            ).await;
                        }
                        Err(_) => send_error(&tx, ErrorCode::BadFrame, "undecodable frame").await,
                    }
                }

                // 已被本实例的新登录顶替：停止处理旧连接的帧。
                if let Some(current) = account
                    && !state.is_current_connection(current, conn_id)
                {
                    break;
                }
            }
            _ = kick_rx.recv() => {
                send_error(&tx, ErrorCode::SessionReplaced, "signed in elsewhere").await;
                break;
            }
        }
    }

    if let Some(task) = pubsub_task {
        task.abort();
    }
    if let Some(task) = presence_task {
        task.abort();
    }
    if let Some(account) = account {
        state.remove_connection(account, conn_id);
        if let Err(error) = state.valkey.clear_presence(account).await {
            eprintln!("clear presence failed: {error}");
        }
    }
    writer.abort();
}

#[allow(clippy::too_many_arguments)]
async fn handle_frame(
    state: &AppState,
    account: &mut Option<AccountId>,
    conn_id: u64,
    tx: &mpsc::Sender<Frame>,
    kick_tx: &mpsc::Sender<()>,
    pubsub_task: &mut Option<JoinHandle<()>>,
    presence_task: &mut Option<JoinHandle<()>>,
    frame: Frame,
) {
    match frame {
        Frame::Register(registration) => {
            if Ed25519PublicKey::from_slice(&registration.ed25519_pub).is_err() {
                send_error(tx, ErrorCode::BadFrame, "invalid ed25519 public key").await;
                return;
            }
            match db::insert_account(&state.db, &registration).await {
                Ok(true) => {
                    state.mark_known(registration.account_id);
                    send_frame(
                        tx,
                        Frame::RegisterAck {
                            account_id: registration.account_id,
                        },
                    )
                    .await;
                }
                Ok(false) => {
                    send_error(
                        tx,
                        ErrorCode::AlreadyRegistered,
                        "account id already registered",
                    )
                    .await;
                }
                Err(error) => {
                    eprintln!("register failed: {error}");
                    send_error(tx, ErrorCode::Internal, "database error").await;
                }
            }
        }

        Frame::ChallengeRequest { account_id } => {
            match state
                .valkey
                .check_rate_limit(
                    "ch",
                    account_id,
                    CHALLENGE_RATE_LIMIT_PER_MINUTE,
                    RATE_WINDOW_SECS,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    state.count_rejected();
                    send_error(tx, ErrorCode::RateLimited, "too many challenges").await;
                    return;
                }
                Err(error) => {
                    eprintln!("challenge rate limit failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                    return;
                }
            }

            match db::load_account(&state.db, account_id).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    send_error(tx, ErrorCode::UnknownAccount, "unknown account").await;
                    return;
                }
                Err(error) => {
                    eprintln!("challenge lookup failed: {error}");
                    send_error(tx, ErrorCode::Internal, "database error").await;
                    return;
                }
            }

            let mut nonce = [0u8; 32];
            if getrandom::fill(&mut nonce).is_err() {
                send_error(tx, ErrorCode::Internal, "random source unavailable").await;
                return;
            }
            let account_hash = state.valkey.hmac_account(account_id);
            if let Err(error) = state.valkey.set_challenge(&nonce, &account_hash).await {
                eprintln!("challenge store failed: {error}");
                send_error(tx, ErrorCode::Internal, "valkey error").await;
                return;
            }
            send_frame(tx, Frame::Challenge { nonce }).await;
        }

        Frame::Login {
            account_id,
            nonce,
            signature,
        } => {
            let expected = match state.valkey.take_challenge(&nonce).await {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("challenge take failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                    return;
                }
            };
            let Some(expected_hash) = expected else {
                send_error(tx, ErrorCode::ChallengeExpired, "no pending challenge").await;
                return;
            };
            if expected_hash != state.valkey.hmac_account(account_id) {
                send_error(tx, ErrorCode::BadSignature, "challenge mismatch").await;
                return;
            }

            let stored = match db::load_account(&state.db, account_id).await {
                Ok(Some(stored)) => stored,
                Ok(None) => {
                    send_error(tx, ErrorCode::UnknownAccount, "unknown account").await;
                    return;
                }
                Err(error) => {
                    eprintln!("login lookup failed: {error}");
                    send_error(tx, ErrorCode::Internal, "database error").await;
                    return;
                }
            };

            let Ok(public_key) = Ed25519PublicKey::from_slice(&stored.ed25519_pub) else {
                send_error(tx, ErrorCode::Internal, "stored key is corrupt").await;
                return;
            };
            let Ok(signature) = Ed25519Signature::from_slice(signature.as_bytes()) else {
                send_error(tx, ErrorCode::BadSignature, "malformed signature").await;
                return;
            };
            if public_key
                .verify(&login_payload(&account_id, &nonce), &signature)
                .is_err()
            {
                send_error(tx, ErrorCode::BadSignature, "signature mismatch").await;
                return;
            }

            *account = Some(account_id);
            state.mark_known(account_id);

            // D10：同一账号单会话。本实例的直接踢，跨实例的靠 presence + 频道通知。
            let previous = state.connections().insert(
                account_id,
                Connection {
                    conn_id,
                    tx: tx.clone(),
                    kick: kick_tx.clone(),
                },
            );
            if let Some(previous) = previous {
                let _ = previous.kick.try_send(());
            }

            match state.valkey.take_presence(account_id).await {
                Ok(Some(previous_instance)) if previous_instance != state.valkey.instance_id() => {
                    if let Err(error) = state.valkey.publish(account_id, "k").await {
                        eprintln!("kick publish failed: {error}");
                    }
                }
                Ok(_) => {}
                Err(error) => eprintln!("presence update failed: {error}"),
            }

            // 订阅唤醒频道；Pub/Sub 丢失不影响正确性，登录时的 flush 会兜底。
            match state.valkey.subscribe(account_id).await {
                Ok(mut pubsub) => {
                    let state = state.clone();
                    *pubsub_task = Some(tokio::spawn(async move {
                        let mut messages = pubsub.on_message();
                        while let Some(message) = messages.next().await {
                            let payload = message.get_payload::<String>().unwrap_or_default();
                            if payload == "k" {
                                if let Some(connection) =
                                    state.connections().get(&account_id).cloned()
                                {
                                    let _ = connection.kick.try_send(());
                                }
                            } else {
                                flush_account(&state, account_id).await;
                            }
                        }
                    }));
                }
                Err(error) => eprintln!("pubsub subscribe failed: {error}"),
            }

            // presence 心跳；被顶替后 refresh 返回 false，任务自行退出。
            {
                let state = state.clone();
                *presence_task = Some(tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(PRESENCE_REFRESH_INTERVAL);
                    loop {
                        ticker.tick().await;
                        match state.valkey.refresh_presence(account_id).await {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(error) => {
                                eprintln!("presence refresh failed: {error}");
                                break;
                            }
                        }
                    }
                }));
            }

            send_frame(tx, Frame::LoginAck { account_id }).await;
            flush_account(state, account_id).await;
        }

        Frame::UploadPreKeys { prekeys } => {
            let Some(account_id) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };
            match state.valkey.store_prekeys(account_id, &prekeys).await {
                Ok(stored) => {
                    send_frame(
                        tx,
                        Frame::UploadPreKeysAck {
                            stored: stored as u16,
                        },
                    )
                    .await;
                }
                Err(error) => {
                    eprintln!("prekey store failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                }
            }
        }

        Frame::FetchPreKey { account_id } => {
            if account.is_none() {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            }

            let stored = match db::load_account(&state.db, account_id).await {
                Ok(Some(stored)) => stored,
                Ok(None) => {
                    send_error(tx, ErrorCode::UnknownAccount, "unknown account").await;
                    return;
                }
                Err(error) => {
                    eprintln!("prekey lookup failed: {error}");
                    send_error(tx, ErrorCode::Internal, "database error").await;
                    return;
                }
            };

            match state.valkey.take_prekey(account_id).await {
                Ok(Some(prekey)) => {
                    send_frame(
                        tx,
                        Frame::PreKeyBundle(PreKeyBundle {
                            account_id,
                            ed25519_pub: stored.ed25519_pub,
                            curve25519_pub: stored.curve25519_pub,
                            one_time_key_id: prekey.key_id,
                            one_time_key: prekey.public_key,
                        }),
                    )
                    .await;
                }
                Ok(None) => {
                    send_error(
                        tx,
                        ErrorCode::PreKeyUnavailable,
                        "no one-time key available",
                    )
                    .await;
                }
                Err(error) => {
                    eprintln!("prekey take failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                }
            }
        }

        Frame::Send(envelope) => {
            let Some(sender) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };
            if !state.is_current_connection(sender, conn_id) {
                send_error(tx, ErrorCode::SessionReplaced, "signed in elsewhere").await;
                return;
            }
            if envelope.from != sender {
                send_error(
                    tx,
                    ErrorCode::BadFrame,
                    "envelope from does not match session",
                )
                .await;
                return;
            }
            let recipient = envelope.to;
            if !state.is_known(recipient) {
                send_error(tx, ErrorCode::UnknownAccount, "unknown recipient").await;
                return;
            }

            match state
                .valkey
                .check_rate_limit(
                    "msg",
                    sender,
                    MESSAGE_RATE_LIMIT_PER_MINUTE,
                    RATE_WINDOW_SECS,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    state.count_rejected();
                    send_error(tx, ErrorCode::RateLimited, "sending too fast").await;
                    return;
                }
                Err(error) => {
                    eprintln!("message rate limit failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                    return;
                }
            }

            let Ok(bytes) = encode_envelope(&envelope) else {
                send_error(tx, ErrorCode::BadFrame, "invalid envelope").await;
                return;
            };

            // 大消息在途上限：防止少量 1MB 消息吃光网关内存。
            let _permit = if bytes.len() > BIG_MESSAGE_BYTES {
                match state.big_messages().acquire().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        send_error(tx, ErrorCode::Internal, "big message limiter closed").await;
                        return;
                    }
                }
            } else {
                None
            };

            let entry_id = match state.valkey.enqueue(recipient, &bytes).await {
                Ok(entry_id) => entry_id,
                Err(error) => {
                    eprintln!("enqueue failed: {error}");
                    send_error(tx, ErrorCode::Internal, "valkey error").await;
                    return;
                }
            };
            state.count_forwarded();

            if state.connections().contains_key(&recipient) {
                flush_account(state, recipient).await;
            } else if let Err(error) = state.valkey.publish(recipient, &entry_id).await {
                eprintln!("publish failed: {error}");
            }

            send_frame(tx, Frame::SendAck { msg_id: entry_id }).await;
        }

        Frame::DeliverAck { msg_id } => {
            let Some(recipient) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };
            if let Err(error) = state.valkey.ack(recipient, &msg_id).await {
                eprintln!("ack failed: {error}");
            }
        }

        // 其余帧要么是服务端 → 客户端方向，要么必须已认证；一律按坏帧处理。
        Frame::RegisterAck { .. }
        | Frame::Challenge { .. }
        | Frame::LoginAck { .. }
        | Frame::UploadPreKeysAck { .. }
        | Frame::PreKeyBundle(_)
        | Frame::Deliver { .. }
        | Frame::SendAck { .. } => {
            send_error(tx, ErrorCode::BadFrame, "unexpected frame from client").await;
        }
        Frame::Error { .. } => {}
    }
}

/// 把该账号队列里全部未 D-ack 的密文按顺序推给本实例持有的连接。
async fn flush_account(state: &AppState, account: AccountId) {
    let Some(connection) = state.connections().get(&account).cloned() else {
        return;
    };

    let entries = match state.valkey.queued(account).await {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("queue read failed: {error}");
            return;
        }
    };

    for (entry_id, bytes) in entries {
        let Ok(envelope) = sme_proto::decode_envelope(&bytes) else {
            continue;
        };
        if connection
            .tx
            .send(Frame::Deliver {
                msg_id: entry_id,
                envelope,
            })
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn send_frame(tx: &mpsc::Sender<Frame>, frame: Frame) {
    let _ = tx.send(frame).await;
}

async fn send_error(tx: &mpsc::Sender<Frame>, code: ErrorCode, detail: &str) {
    let _ = tx
        .send(Frame::Error {
            code,
            detail: detail.to_string(),
        })
        .await;
}
