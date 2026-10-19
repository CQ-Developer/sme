//! D28: interactive SAS verification over the Olm channel.
//!
//! Both sides derive the same 7 emoji / 3 decimal code, exchange MACs bound to both
//! identity key pairs, and only then mark the TOFU pin as verified.

use sme_client_core::{Action, Client, CoreError};
use sme_proto::{AccountId, Frame, PreKeyBundle};
use vodozemac::olm::Account;

fn client_pair() -> (Client, Client, AccountId, AccountId) {
    let alice_id = AccountId::random();
    let bob_id = AccountId::random();
    let alice = Client::new(alice_id, Account::new());
    let bob = Client::new(bob_id, Account::new());
    (alice, bob, alice_id, bob_id)
}

fn bob_bundle(bob: &mut Client, bob_id: AccountId) -> PreKeyBundle {
    let actions = bob.prekey_upload(5);
    let prekeys = actions
        .iter()
        .find_map(|action| match action {
            Action::Send(Frame::UploadPreKeys { prekeys }) => Some(prekeys.clone()),
            _ => None,
        })
        .expect("prekey upload");
    let identity = bob.account().identity_keys();
    PreKeyBundle {
        account_id: bob_id,
        ed25519_pub: *identity.ed25519.as_bytes(),
        curve25519_pub: *identity.curve25519.as_bytes(),
        one_time_key_id: prekeys[0].key_id.clone(),
        one_time_key: prekeys[0].public_key,
    }
}

fn take_send(actions: &[Action]) -> Frame {
    actions
        .iter()
        .find_map(|action| match action {
            Action::Send(frame @ Frame::Send(_)) => Some(frame.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an encrypted message envelope, got {actions:?}"))
}

fn take_code(actions: &[Action]) -> ([u8; 7], (u16, u16, u16)) {
    actions
        .iter()
        .find_map(|action| match action {
            Action::SasCode {
                emojis, decimals, ..
            } => Some((*emojis, *decimals)),
            _ => None,
        })
        .expect("expected a SasCode action")
}

/// Establish a bidirectional Olm session and pin both identities.
fn connected_pair() -> (Client, Client, AccountId, AccountId) {
    let (mut alice, mut bob, alice_id, bob_id) = client_pair();
    let bundle = bob_bundle(&mut bob, bob_id);
    alice.handle_frame(Frame::PreKeyBundle(bundle));
    assert!(alice.peer_pin(bob_id).is_some());

    let actions = alice.send_text(bob_id, "hello").unwrap();
    let Frame::Send(envelope) = take_send(&actions) else {
        panic!("expected an envelope");
    };
    bob.handle_frame(Frame::Deliver {
        msg_id: "bootstrap".to_string(),
        envelope,
    });

    // The inbound side learns the sender's Ed25519 from the directory.
    let alice_identity = alice.account().identity_keys();
    bob.handle_frame(Frame::IdentityKeys {
        account_id: alice_id,
        ed25519_pub: *alice_identity.ed25519.as_bytes(),
        curve25519_pub: *alice_identity.curve25519.as_bytes(),
    });
    assert!(bob.peer_pin(alice_id).is_some());

    (alice, bob, alice_id, bob_id)
}

#[test]
fn both_sides_derive_the_same_code_and_verify_after_both_confirmations() {
    let (mut alice, mut bob, alice_id, bob_id) = connected_pair();

    let actions = alice.start_sas(bob_id).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::SasStarted { peer } if *peer == bob_id))
    );
    let Frame::Send(start) = take_send(&actions) else {
        panic!("expected a SAS Start envelope");
    };

    let bob_actions = bob.handle_frame(Frame::Deliver {
        msg_id: "sas-1".to_string(),
        envelope: start,
    });
    let bob_code = take_code(&bob_actions);
    let Frame::Send(public_key) = take_send(&bob_actions) else {
        panic!("expected a SAS PublicKey envelope");
    };

    let alice_actions = alice.handle_frame(Frame::Deliver {
        msg_id: "sas-2".to_string(),
        envelope: public_key,
    });
    let alice_code = take_code(&alice_actions);
    assert_eq!(alice_code.0, bob_code.0, "emoji codes must match");
    assert_eq!(alice_code.1, bob_code.1, "decimal codes must match");

    // Alice confirms first: her MAC reaches Bob, who is not yet locally confirmed.
    let actions = alice.confirm_sas(bob_id).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::SasLocalConfirmed { peer } if *peer == bob_id))
    );
    assert!(!alice.is_peer_verified(bob_id));
    let Frame::Send(alice_mac) = take_send(&actions) else {
        panic!("expected Alice's MAC envelope");
    };
    let bob_actions = bob.handle_frame(Frame::Deliver {
        msg_id: "sas-3".to_string(),
        envelope: alice_mac,
    });
    assert!(
        bob_actions
            .iter()
            .any(|action| matches!(action, Action::SasPeerConfirmed { peer } if *peer == alice_id))
    );
    assert!(!bob.is_peer_verified(alice_id));

    // Bob confirms: his MAC completes the exchange on both sides.
    let actions = bob.confirm_sas(alice_id).unwrap();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::SasVerified { peer } if *peer == alice_id))
    );
    assert!(bob.is_peer_verified(alice_id));
    let Frame::Send(bob_mac) = take_send(&actions) else {
        panic!("expected Bob's MAC envelope");
    };
    let alice_actions = alice.handle_frame(Frame::Deliver {
        msg_id: "sas-4".to_string(),
        envelope: bob_mac,
    });
    assert!(
        alice_actions
            .iter()
            .any(|action| matches!(action, Action::SasVerified { peer } if *peer == bob_id))
    );
    assert!(alice.is_peer_verified(bob_id));
}

#[test]
fn sas_requires_a_pin_and_an_established_session() {
    let (mut alice, bob, _alice_id, bob_id) = client_pair();

    assert!(matches!(
        alice.start_sas(bob_id).unwrap_err(),
        CoreError::NoPin(peer) if peer == bob_id
    ));

    // Pin without a session.
    let actions = alice.fetch_prekey(bob_id);
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Send(_)))
    );
    let identity = bob.account().identity_keys();
    alice.handle_frame(Frame::IdentityKeys {
        account_id: bob_id,
        ed25519_pub: *identity.ed25519.as_bytes(),
        curve25519_pub: *identity.curve25519.as_bytes(),
    });
    assert!(matches!(
        alice.start_sas(bob_id).unwrap_err(),
        CoreError::NoSession(peer) if peer == bob_id
    ));

    // Establishing the session makes SAS available, but only one verifies at a time.
    let (mut alice, _bob, _alice_id, bob_id) = connected_pair();
    alice.start_sas(bob_id).unwrap();
    assert!(matches!(
        alice.start_sas(bob_id).unwrap_err(),
        CoreError::SasInProgress
    ));
    let actions = alice.cancel_sas(bob_id);
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::SasCancelled { peer } if *peer == bob_id))
    );
}

#[test]
fn identity_change_clears_sas_verification() {
    let (mut alice, mut bob, alice_id, bob_id) = connected_pair();

    let actions = alice.start_sas(bob_id).unwrap();
    let Frame::Send(start) = take_send(&actions) else {
        panic!("expected Start");
    };
    let bob_actions = bob.handle_frame(Frame::Deliver {
        msg_id: "sas-a".to_string(),
        envelope: start,
    });
    let Frame::Send(public_key) = take_send(&bob_actions) else {
        panic!("expected PublicKey");
    };
    alice.handle_frame(Frame::Deliver {
        msg_id: "sas-b".to_string(),
        envelope: public_key,
    });

    let actions = alice.confirm_sas(bob_id).unwrap();
    let Frame::Send(alice_mac) = take_send(&actions) else {
        panic!("expected Alice MAC");
    };
    bob.handle_frame(Frame::Deliver {
        msg_id: "sas-c".to_string(),
        envelope: alice_mac,
    });
    let actions = bob.confirm_sas(alice_id).unwrap();
    let Frame::Send(bob_mac) = take_send(&actions) else {
        panic!("expected Bob MAC");
    };
    alice.handle_frame(Frame::Deliver {
        msg_id: "sas-d".to_string(),
        envelope: bob_mac,
    });
    assert!(alice.is_peer_verified(bob_id));

    // A changed directory identity must clear the verified state.
    let actions = alice.handle_frame(Frame::IdentityKeys {
        account_id: bob_id,
        ed25519_pub: [0x42; 32],
        curve25519_pub: [0x24; 32],
    });
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::PeerKeyChanged { peer, .. } if *peer == bob_id))
    );
    assert!(!alice.is_peer_verified(bob_id));
    assert!(alice.is_peer_blocked(bob_id));
}

#[test]
fn sas_mac_over_mismatched_identity_keys_is_rejected() {
    let (mut alice, mut bob, alice_id, bob_id) = client_pair();
    let bundle = bob_bundle(&mut bob, bob_id);
    alice.handle_frame(Frame::PreKeyBundle(bundle));

    let actions = alice.send_text(bob_id, "hello").unwrap();
    let Frame::Send(envelope) = take_send(&actions) else {
        panic!("expected an envelope");
    };
    bob.handle_frame(Frame::Deliver {
        msg_id: "mismatch-boot".to_string(),
        envelope,
    });

    // Give Bob a wrong Ed25519 half for Alice (the Curve25519 half stays correct so the
    // inbound pre-key check does not block). The ephemeral SAS code still matches, but the
    // identity MAC must fail because the pins disagree.
    let identity = alice.account().identity_keys();
    bob.handle_frame(Frame::IdentityKeys {
        account_id: alice_id,
        ed25519_pub: [0x99; 32],
        curve25519_pub: *identity.curve25519.as_bytes(),
    });

    let actions = alice.start_sas(bob_id).unwrap();
    let Frame::Send(start) = take_send(&actions) else {
        panic!("expected Start");
    };
    let bob_actions = bob.handle_frame(Frame::Deliver {
        msg_id: "mismatch-1".to_string(),
        envelope: start,
    });
    let Frame::Send(public_key) = take_send(&bob_actions) else {
        panic!("expected PublicKey");
    };
    alice.handle_frame(Frame::Deliver {
        msg_id: "mismatch-2".to_string(),
        envelope: public_key,
    });

    let actions = alice.confirm_sas(bob_id).unwrap();
    let Frame::Send(mac) = take_send(&actions) else {
        panic!("expected MAC");
    };
    let bob_actions = bob.handle_frame(Frame::Deliver {
        msg_id: "mismatch-3".to_string(),
        envelope: mac,
    });

    assert!(
        bob_actions
            .iter()
            .any(|action| matches!(action, Action::SasFailed { peer } if *peer == alice_id))
    );
    assert!(!bob.is_peer_verified(alice_id));
}
