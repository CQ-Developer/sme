//! I10: a TOFU pin must never be silently rewritten, and identity changes must be reported.
//!
//! The pin is set on first contact (prekey bundle or directory lookup), compared on every
//! later observation, and a mismatch blocks sending to that peer until the pin matches again.

use sme_client_core::{Action, Client, CoreError, PeerPin};
use sme_proto::{AccountId, Frame, PreKeyBundle};
use vodozemac::olm::Account;

fn client_pair() -> (Client, Client, AccountId, AccountId) {
    let alice_id = AccountId::random();
    let bob_id = AccountId::random();
    let alice = Client::new(alice_id, Account::new());
    let bob = Client::new(bob_id, Account::new());
    (alice, bob, alice_id, bob_id)
}

fn bundle_for(client: &mut Client, account_id: AccountId) -> PreKeyBundle {
    let actions = client.prekey_upload(5);
    let prekeys = actions
        .iter()
        .find_map(|action| match action {
            Action::Send(Frame::UploadPreKeys { prekeys }) => Some(prekeys.clone()),
            _ => None,
        })
        .expect("prekey upload actions");
    let identity = client.account().identity_keys();

    PreKeyBundle {
        account_id,
        ed25519_pub: *identity.ed25519.as_bytes(),
        curve25519_pub: *identity.curve25519.as_bytes(),
        one_time_key_id: prekeys[0].key_id.clone(),
        one_time_key: prekeys[0].public_key,
    }
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

fn same_pin(actions: &[Action], peer: AccountId, expected: PeerPin) -> bool {
    actions.iter().any(|action| {
        matches!(
            action,
            Action::PeerPinned { peer: action_peer, pin }
                if *action_peer == peer && *pin == expected
        )
    })
}

#[test]
fn first_bundle_pins_and_restores_confirm_the_same_keys() {
    let (mut alice, mut bob, _alice_id, bob_id) = client_pair();
    let bundle = bundle_for(&mut bob, bob_id);
    let expected = PeerPin {
        ed25519_pub: bundle.ed25519_pub,
        curve25519_pub: bundle.curve25519_pub,
    };

    let actions = alice.handle_frame(Frame::PreKeyBundle(bundle.clone()));
    assert!(same_pin(&actions, bob_id, expected));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Persist))
    );
    assert_eq!(alice.peer_pin(bob_id), Some(&expected));
    assert!(!alice.is_peer_blocked(bob_id));

    // The same keys on a later observation are a confirmation, not a new pin.
    let actions = alice.handle_frame(Frame::PreKeyBundle(bundle));
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::PeerPinned { .. }))
    );
    assert_eq!(alice.peer_pin(bob_id), Some(&expected));
}

#[test]
fn changed_bundle_does_not_overwrite_the_pin_and_blocks_sends() {
    let (mut alice, mut bob, _alice_id, bob_id) = client_pair();
    let bundle = bundle_for(&mut bob, bob_id);
    let pinned = PeerPin {
        ed25519_pub: bundle.ed25519_pub,
        curve25519_pub: bundle.curve25519_pub,
    };
    alice.handle_frame(Frame::PreKeyBundle(bundle.clone()));

    let mut changed = bundle.clone();
    changed.ed25519_pub = [0x42; 32];
    changed.curve25519_pub = [0x24; 32];
    let actions = alice.handle_frame(Frame::PreKeyBundle(changed));

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::PeerKeyChanged { peer, pinned: old, observed: Some(observed) }
            if *peer == bob_id && *old == pinned && observed.ed25519_pub == [0x42; 32]
    )));
    assert_eq!(
        alice.peer_pin(bob_id),
        Some(&pinned),
        "the stored pin must never be replaced by an observed key"
    );
    assert!(alice.is_peer_blocked(bob_id));
    assert!(matches!(
        alice.send_text(bob_id, "blocked").unwrap_err(),
        CoreError::PeerKeyChanged(peer) if peer == bob_id
    ));

    // A later observation of the original keys clears the block and is reported.
    let actions = alice.handle_frame(Frame::PreKeyBundle(bundle));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::PeerKeyConfirmed { peer } if *peer == bob_id))
    );
    assert!(!alice.is_peer_blocked(bob_id));
    assert!(alice.send_text(bob_id, "works again").is_ok());
    assert_eq!(alice.peer_pin(bob_id), Some(&pinned));
}

#[test]
fn identity_directory_lookup_follows_the_same_pin_rules() {
    let (mut alice, _bob, _alice_id, bob_id) = client_pair();
    let pinned = PeerPin {
        ed25519_pub: [0x11; 32],
        curve25519_pub: [0x22; 32],
    };
    let actions = alice.handle_frame(Frame::IdentityKeys {
        account_id: bob_id,
        ed25519_pub: pinned.ed25519_pub,
        curve25519_pub: pinned.curve25519_pub,
    });
    assert!(same_pin(&actions, bob_id, pinned));

    let actions = alice.handle_frame(Frame::IdentityKeys {
        account_id: bob_id,
        ed25519_pub: [0x33; 32],
        curve25519_pub: [0x44; 32],
    });
    assert!(actions.iter().any(|action| matches!(
        action,
        Action::PeerKeyChanged { peer, observed: Some(observed), .. }
            if *peer == bob_id && observed.curve25519_pub == [0x44; 32]
    )));
    assert_eq!(alice.peer_pin(bob_id), Some(&pinned));

    let actions = alice.handle_frame(Frame::IdentityKeys {
        account_id: bob_id,
        ed25519_pub: pinned.ed25519_pub,
        curve25519_pub: pinned.curve25519_pub,
    });
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::PeerKeyConfirmed { peer } if *peer == bob_id))
    );
}

#[test]
fn inbound_prekey_with_a_different_curve_key_is_dropped_and_reported() {
    let (mut alice, mut bob, alice_id, bob_id) = client_pair();

    // Pin Bob's real identity first.
    let bob_bundle = bundle_for(&mut bob, bob_id);
    let pinned = PeerPin {
        ed25519_pub: bob_bundle.ed25519_pub,
        curve25519_pub: bob_bundle.curve25519_pub,
    };
    alice.handle_frame(Frame::PreKeyBundle(bob_bundle));

    // An impostor controls the same account ID but a different identity key.
    let mut impostor = Client::new(bob_id, Account::new());
    let alice_bundle = bundle_for(&mut alice, alice_id);
    impostor.handle_frame(Frame::PreKeyBundle(alice_bundle));
    let Frame::Send(envelope) = first_send(impostor.send_text(alice_id, "impersonation").unwrap())
    else {
        panic!("expected Send");
    };

    let actions = alice.handle_frame(Frame::Deliver {
        msg_id: "impostor-1".to_string(),
        envelope,
    });

    assert!(actions.iter().any(|action| matches!(
        action,
        Action::PeerKeyChanged { peer, pinned: old, observed: None }
            if *peer == bob_id && *old == pinned
    )));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Send(Frame::DeliverAck { msg_id }) if msg_id == "impostor-1"))
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Received { .. })),
        "a message with a changed identity must not reach the UI buffer"
    );
    assert!(alice.buffer().is_empty());
    assert_eq!(alice.peer_pin(bob_id), Some(&pinned));
}

#[test]
fn peer_pin_flat_encoding_roundtrips() {
    let pin = PeerPin {
        ed25519_pub: [0xAB; 32],
        curve25519_pub: [0xCD; 32],
    };
    assert_eq!(PeerPin::from_bytes(&pin.to_bytes()), Some(pin));
    assert_eq!(PeerPin::from_bytes(&[0u8; 63]), None);
    assert_eq!(PeerPin::from_bytes(&[0u8; 65]), None);
}
