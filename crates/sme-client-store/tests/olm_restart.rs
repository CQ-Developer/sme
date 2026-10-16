//! M1 退出标准：账号与 Olm 会话跨「重启」保持不变，棘轮可以继续收发。
//!
//! 真实的进程重启由「丢弃内存对象 + 重新 `Keystore::open`」模拟；
//! 落盘走 vodozemac 公开 API 的 `pickle().encrypt(kek)`（plan.md §6.1）。

mod common;

use common::TestDir;
use sme_client_store::Keystore;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Alice 向 Bob 发起 Olm 握手，双方各自拿到会话。
fn establish_sessions() -> (Account, Account, Session, Session) {
    let alice = Account::new();
    let mut bob = Account::new();

    bob.generate_one_time_keys(1);
    let bob_identity = bob.identity_keys().curve25519;
    let bob_one_time = *bob
        .one_time_keys()
        .values()
        .next()
        .expect("刚生成过 prekey");
    bob.mark_keys_as_published();

    let mut alice_session = alice
        .create_outbound_session(SessionConfig::default(), bob_identity, bob_one_time)
        .unwrap();

    let pre_key = match alice_session.encrypt("hello bob").unwrap() {
        OlmMessage::PreKey(message) => message,
        OlmMessage::Normal(_) => panic!("首条消息必须是 pre-key 消息"),
    };
    let inbound = bob
        .create_inbound_session(
            SessionConfig::default(),
            alice.identity_keys().curve25519,
            &pre_key,
        )
        .unwrap();
    assert_eq!(inbound.plaintext, b"hello bob".to_vec());

    (alice, bob, alice_session, inbound.session)
}

#[test]
fn account_and_session_survive_restart() {
    let dir = TestDir::new("olm-restart");
    let path = dir.join("keystore.bin");

    let (alice, _bob, alice_session, mut bob_session) = establish_sessions();
    let identity_before = alice.identity_keys();
    let session_id = alice_session.session_id();

    let mut keystore = Keystore::create(&path, PASSWORD).unwrap();
    keystore.save_account(&alice).unwrap();
    keystore.save_session(&alice_session).unwrap();
    keystore.save().unwrap();

    // 模拟重启：内存里的 Alice 全部丢弃，只从磁盘重新打开。
    drop(alice_session);
    drop(alice);

    let keystore = Keystore::open(&path, PASSWORD).unwrap();
    let alice_restored = keystore.load_account().unwrap().expect("账号必须能恢复");
    assert_eq!(alice_restored.identity_keys(), identity_before);

    assert_eq!(keystore.session_ids(), vec![session_id.clone()]);
    let mut alice_session_restored = keystore
        .load_session(&session_id)
        .unwrap()
        .expect("会话必须能恢复");
    assert_eq!(alice_session_restored.session_id(), session_id);

    // 棘轮连续性：Bob 用重启前的会话发消息，恢复后的 Alice 必须能解开。
    let message = bob_session.encrypt("after restart").unwrap();
    assert_eq!(
        alice_session_restored.decrypt(&message).unwrap(),
        b"after restart".to_vec()
    );

    // 反向：恢复后的 Alice 发消息，Bob 必须能解开。
    let message = alice_session_restored
        .encrypt("from restored alice")
        .unwrap();
    assert_eq!(
        bob_session.decrypt(&message).unwrap(),
        b"from restored alice".to_vec()
    );
}

#[test]
fn empty_keystore_has_no_account_or_sessions() {
    let dir = TestDir::new("olm-empty");
    let path = dir.join("keystore.bin");

    let keystore = Keystore::create(&path, PASSWORD).unwrap();
    keystore.save().unwrap();

    let keystore = Keystore::open(&path, PASSWORD).unwrap();
    assert!(keystore.load_account().unwrap().is_none());
    assert!(keystore.load_session("does-not-exist").unwrap().is_none());
    assert!(keystore.session_ids().is_empty());
}
