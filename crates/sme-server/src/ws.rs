//! WebSocket 状态机：注册 → 挑战-签名登录 → 预密钥 / 密文转发。
//!
//! 帧的 `payload` 不解析、不落日志；所有错误都以 `Frame::Error` 回给对端。

use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, PreKeyBundle, decode, encode, login_payload,
};
use tokio::sync::mpsc;
use vodozemac::{Ed25519PublicKey, Ed25519Signature};

use crate::db;
use crate::state::{
    AppState, Challenge, Connection, MAX_PENDING_CHALLENGES, MAX_QUEUED_PER_RECIPIENT,
    MAX_STORED_PREKEYS, QueuedMessage,
};

/// 写方向缓冲深度：够了就行，避免慢客户端吃内存。
const WRITE_QUEUE: usize = 128;

/// 登录挑战有效期。
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

pub async fn ws_handler(State(state): State<AppState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| async move {
        handle_socket(state, socket).await;
    })
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Frame>(WRITE_QUEUE);

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

    while let Some(message) = stream.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => break,
        };
        match message {
            Message::Binary(bytes) => match decode(&bytes) {
                Ok(frame) => handle_frame(&state, &mut account, conn_id, &tx, frame).await,
                Err(_) => {
                    send_error(&tx, ErrorCode::BadFrame, "undecodable frame").await;
                }
            },
            Message::Close(_) => break,
            _ => {}
        }
    }

    if let Some(account) = account {
        let mut connections = state.connections();
        if connections
            .get(&account)
            .is_some_and(|connection| connection.conn_id == conn_id)
        {
            connections.remove(&account);
        }
    }
    writer.abort();
}

async fn handle_frame(
    state: &AppState,
    account: &mut Option<AccountId>,
    conn_id: u64,
    tx: &mpsc::Sender<Frame>,
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
                    state.known().insert(registration.account_id);
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

            let rate_limited = {
                let mut challenges = state.challenges();
                if challenges.len() >= MAX_PENDING_CHALLENGES {
                    let now = std::time::Instant::now();
                    challenges.retain(|_, challenge| {
                        now.duration_since(challenge.issued_at) <= CHALLENGE_TTL
                    });
                }
                if challenges.len() >= MAX_PENDING_CHALLENGES {
                    true
                } else {
                    challenges.insert(
                        account_id,
                        Challenge {
                            nonce,
                            issued_at: std::time::Instant::now(),
                        },
                    );
                    false
                }
            };
            if rate_limited {
                send_error(tx, ErrorCode::RateLimited, "too many pending challenges").await;
                return;
            }
            send_frame(tx, Frame::Challenge { nonce }).await;
        }

        Frame::Login {
            account_id,
            signature,
        } => {
            let challenge = state.challenges().remove(&account_id);
            let Some(challenge) = challenge else {
                send_error(tx, ErrorCode::ChallengeExpired, "no pending challenge").await;
                return;
            };
            if challenge.issued_at.elapsed() > CHALLENGE_TTL {
                send_error(tx, ErrorCode::ChallengeExpired, "challenge expired").await;
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
                .verify(&login_payload(&account_id, &challenge.nonce), &signature)
                .is_err()
            {
                send_error(tx, ErrorCode::BadSignature, "signature mismatch").await;
                return;
            }

            *account = Some(account_id);
            state.known().insert(account_id);

            let previous = state.connections().insert(
                account_id,
                Connection {
                    conn_id,
                    tx: tx.clone(),
                },
            );
            if let Some(previous) = previous {
                // D10：单会话，新登录踢掉旧会话并明确告知。
                let _ = previous.tx.try_send(error_frame(
                    ErrorCode::SessionReplaced,
                    "signed in from another connection",
                ));
            }

            send_frame(tx, Frame::LoginAck { account_id }).await;
            flush_queue(state, account_id).await;
        }

        Frame::UploadPreKeys { prekeys } => {
            let Some(account_id) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };

            let stored = {
                let mut all_prekeys = state.prekeys();
                let queue = all_prekeys.entry(account_id).or_default();
                for prekey in prekeys {
                    if !queue
                        .iter()
                        .any(|existing| existing.key_id == prekey.key_id)
                    {
                        queue.push_back(prekey);
                    }
                }
                while queue.len() > MAX_STORED_PREKEYS {
                    queue.pop_front();
                }
                queue.len()
            };
            send_frame(
                tx,
                Frame::UploadPreKeysAck {
                    stored: stored as u16,
                },
            )
            .await;
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

            let prekey = state
                .prekeys()
                .get_mut(&account_id)
                .and_then(|queue| queue.pop_front());
            let Some(prekey) = prekey else {
                send_error(
                    tx,
                    ErrorCode::PreKeyUnavailable,
                    "no one-time key available",
                )
                .await;
                return;
            };

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

        Frame::Send(envelope) => {
            let Some(sender) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };
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

            let msg_id = state.next_message_id();
            let message = QueuedMessage {
                msg_id,
                envelope: Envelope {
                    from: sender,
                    ..envelope
                },
            };

            let queue_full = {
                let mut queues = state.queues();
                let queue = queues.entry(recipient).or_default();
                if queue.len() >= MAX_QUEUED_PER_RECIPIENT {
                    true
                } else {
                    queue.push_back(message);
                    false
                }
            };
            if queue_full {
                send_error(tx, ErrorCode::QueueFull, "recipient queue is full").await;
                return;
            }

            send_frame(tx, Frame::SendAck { msg_id }).await;
            deliver_queued(state, recipient, Some(msg_id)).await;
        }

        Frame::DeliverAck { msg_id } => {
            let Some(recipient) = *account else {
                send_error(tx, ErrorCode::NotAuthenticated, "login required").await;
                return;
            };
            let mut queues = state.queues();
            let empty = match queues.get_mut(&recipient) {
                Some(queue) => {
                    queue.retain(|message| message.msg_id != msg_id);
                    queue.is_empty()
                }
                None => false,
            };
            if empty {
                queues.remove(&recipient);
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

/// 按序投递该收件人队列里的消息；不删除，等 D-ack。
async fn flush_queue(state: &AppState, account: AccountId) {
    deliver_queued(state, account, None).await;
}

/// `only_msg_id = None` 时投递队列里全部未 ACK 的消息。
async fn deliver_queued(state: &AppState, account: AccountId, only_msg_id: Option<u64>) {
    let Some(connection) = state.connections().get(&account).cloned() else {
        return;
    };
    let pending: Vec<QueuedMessage> = state
        .queues()
        .get(&account)
        .map(|queue| {
            queue
                .iter()
                .filter(|message| only_msg_id.is_none_or(|msg_id| message.msg_id == msg_id))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    for message in pending {
        if connection
            .tx
            .send(Frame::Deliver {
                msg_id: message.msg_id,
                envelope: message.envelope,
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
    let _ = tx.send(error_frame(code, detail)).await;
}

fn error_frame(code: ErrorCode, detail: &str) -> Frame {
    Frame::Error {
        code,
        detail: detail.to_string(),
    }
}
