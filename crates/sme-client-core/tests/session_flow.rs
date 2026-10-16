//! Pure offline tests for the core state machine: handshake, bidirectional messaging, duplicates and buffer cap.
//!
//! No IO at all (I2 gate); server interaction is covered by `sme-server` integration tests.

use sme_client_core::{Action, Client, CoreError, MESSAGE_BUFFER_LIMIT};
use sme_proto::{AccountId, Frame, MessageBody, OlmMessageKind, PreKeyBundle};
use vodozemac::olm::Account;

fn client_pair() -> (Client, Client, AccountId, AccountId) {
    let alice_id = AccountId::random();
    let bob_id = AccountId::random();
    let alice = Client::new(alice_id, Account::new());
    let bob = Client::new(bob_id, Account::new());
    (alice, bob, alice_id, bob_id)
}

/// Bob generates prekeys and hands one to Alice to build the outbound session.
fn establish(alice: &mut Client, bob: &mut Client, bob_id: AccountId) {
    let actions = bob.prekey_upload(5);
    let Frame::UploadPreKeys { prekeys } = first_send(actions) else {
        panic!("expected UploadPreKeys");
    };

    let bob_identity = bob.account().identity_keys();
    let bundle = PreKeyBundle {
        account_id: bob_id,
        ed25519_pub: *bob_identity.ed25519.as_bytes(),
        curve25519_pub: *bob_identity.curve25519.as_bytes(),
        one_time_key_id: prekeys[0].key_id.clone(),
        one_time_key: prekeys[0].public_key,
    };
    let actions = alice.handle_frame(Frame::PreKeyBundle(bundle));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Persist))
    );
}

fn first_send(actions: Vec<Action>) -> Frame {
    actions
        .into_iter()
        .find_map(|action| match action {
            Action::Send(frame) => Some(frame),
            _ => None,
        })
        .expect("expected an outgoing frame")
}

#[test]
fn handshake_and_bidirectional_messages() {
    let (mut alice, mut bob, alice_id, bob_id) = client_pair();
    establish(&mut alice, &mut bob, bob_id);

    // Alice → Bob
    let Frame::Send(envelope) = first_send(alice.send_text(bob_id, "hello bob").unwrap()) else {
        panic!("expected Send");
    };
    assert_eq!(envelope.kind, OlmMessageKind::PreKey);
    assert_eq!(envelope.to, bob_id);

    let actions = bob.handle_frame(Frame::Deliver {
        msg_id: "1".to_string(),
        envelope,
    });
    assert!(actions.iter().any(
        |action| matches!(action, Action::Received { body: MessageBody::Text { text }, .. } if text == "hello bob")
    ));
    assert_eq!(bob.buffer().len(), 1);

    // Bob -> Alice (Bob already built the inbound session from the pre-key message)
    let Frame::Send(envelope) = first_send(bob.send_text(alice_id, "hi alice").unwrap()) else {
        panic!("expected Send");
    };
    assert_eq!(envelope.kind, OlmMessageKind::Normal);

    let actions = alice.handle_frame(Frame::Deliver {
        msg_id: "2".to_string(),
        envelope,
    });
    assert!(actions.iter().any(
        |action| matches!(action, Action::Received { body: MessageBody::Text { text }, .. } if text == "hi alice")
    ));
    assert_eq!(alice.buffer().len(), 1);
}

#[test]
fn duplicate_delivery_is_acked_but_not_shown() {
    let (mut alice, mut bob, _alice_id, bob_id) = client_pair();
    establish(&mut alice, &mut bob, bob_id);

    let Frame::Send(envelope) = first_send(alice.send_text(bob_id, "only once").unwrap()) else {
        panic!("expected Send");
    };

    let first = bob.handle_frame(Frame::Deliver {
        msg_id: "7".to_string(),
        envelope: envelope.clone(),
    });
    assert!(
        first
            .iter()
            .any(|action| matches!(action, Action::Received { .. }))
    );

    let second = bob.handle_frame(Frame::Deliver {
        msg_id: "7".to_string(),
        envelope,
    });
    assert!(
        second
            .iter()
            .any(|action| matches!(action, Action::DecryptFailed { .. }))
    );
    assert!(second.iter().any(
        |action| matches!(action, Action::Send(Frame::DeliverAck { msg_id }) if msg_id == "7")
    ));
    assert_eq!(
        bob.buffer().len(),
        1,
        "duplicate delivery must not be shown twice"
    );
}

#[test]
fn buffer_drops_the_oldest_messages() {
    let (mut alice, mut bob, _alice_id, bob_id) = client_pair();
    establish(&mut alice, &mut bob, bob_id);

    for i in 0..(MESSAGE_BUFFER_LIMIT + 5) {
        let Frame::Send(envelope) = first_send(alice.send_text(bob_id, &format!("m{i}")).unwrap())
        else {
            panic!("expected Send");
        };
        bob.handle_frame(Frame::Deliver {
            msg_id: i.to_string(),
            envelope,
        });
    }

    assert_eq!(bob.buffer().len(), MESSAGE_BUFFER_LIMIT);
    assert_eq!(bob.buffer().oldest().unwrap().text(), Some("m5"));
    assert_eq!(
        bob.buffer().newest().unwrap().text(),
        Some(format!("m{}", MESSAGE_BUFFER_LIMIT + 4).as_str())
    );
}

#[test]
fn sending_without_a_session_fails() {
    let (mut alice, _bob, _alice_id, bob_id) = client_pair();
    let error = alice.send_text(bob_id, "too early").unwrap_err();
    assert!(matches!(error, CoreError::NoSession(peer) if peer == bob_id));
}

#[test]
fn wipe_clears_messages_and_sessions() {
    let (mut alice, mut bob, alice_id, bob_id) = client_pair();
    establish(&mut alice, &mut bob, bob_id);

    let Frame::Send(envelope) = first_send(alice.send_text(bob_id, "wipe me").unwrap()) else {
        panic!("expected Send");
    };
    bob.handle_frame(Frame::Deliver {
        msg_id: "1".to_string(),
        envelope,
    });
    assert_eq!(bob.buffer().len(), 1);

    bob.wipe();
    assert!(bob.buffer().is_empty());
    assert!(
        matches!(bob.send_text(alice_id, "again").unwrap_err(), CoreError::NoSession(peer) if peer == alice_id)
    );
}

#[test]
fn envelope_addressed_to_someone_else_is_ignored() {
    let (mut alice, mut bob, _alice_id, bob_id) = client_pair();
    establish(&mut alice, &mut bob, bob_id);

    let Frame::Send(mut envelope) = first_send(alice.send_text(bob_id, "not for carol").unwrap())
    else {
        panic!("expected Send");
    };
    envelope.to = AccountId::random();
    let actions = bob.handle_frame(Frame::Deliver {
        msg_id: "9".to_string(),
        envelope,
    });
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::DecryptFailed { .. }))
    );
    assert_eq!(bob.buffer().len(), 0);
}
