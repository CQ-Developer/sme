//! M1 exit criterion: account and Olm sessions survive a "restart" and the ratchet keeps working.
//!
//! A real process restart is simulated by dropping in-memory objects and reopening `Keystore::open`;
//! Persistence goes through vodozemac's public `pickle().encrypt(kek)` API (plan.md §6.1).

mod common;

use common::TestDir;
use sme_client_store::Keystore;
use sme_proto::AccountId;
use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Alice starts the Olm handshake with Bob; both sides end up with a session.
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
    let peer = AccountId::random();

    let mut keystore = Keystore::create(&path, PASSWORD).unwrap();
    keystore.save_account(&alice).unwrap();
    keystore.save_session(peer, &alice_session).unwrap();
    keystore.save().unwrap();

    // Simulate a restart: drop the in-memory Alice entirely and reopen from disk.
    drop(alice_session);
    drop(alice);

    let keystore = Keystore::open(&path, PASSWORD).unwrap();
    let alice_restored = keystore.load_account().unwrap().expect("账号必须能恢复");
    assert_eq!(alice_restored.identity_keys(), identity_before);

    let sessions = keystore.load_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    let (restored_peer, mut alice_session_restored) = sessions.into_iter().next().unwrap();
    assert_eq!(restored_peer, peer);
    assert_eq!(alice_session_restored.session_id(), session_id);

    // Ratchet continuity: Bob sends on the pre-restart session and the restored Alice must decrypt it.
    let message = bob_session.encrypt("after restart").unwrap();
    assert_eq!(
        alice_session_restored.decrypt(&message).unwrap(),
        b"after restart".to_vec()
    );

    // Reverse direction: the restored Alice sends and Bob must decrypt it.
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
    assert!(keystore.load_sessions().unwrap().is_empty());
}
