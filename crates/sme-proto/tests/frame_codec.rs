//! Codec edge cases: every frame round-trips and invalid input is strictly rejected.

use sme_proto::{
    AccountId, Envelope, ErrorCode, Frame, KdfParams, OlmMessageKind, PROTOCOL_VERSION,
    PreKeyBundle, PreKeyUpload, Registration, Signature, decode, decode_envelope, encode,
    encode_envelope,
};

fn sample_envelope() -> Envelope {
    Envelope {
        v: PROTOCOL_VERSION,
        from: AccountId::random(),
        to: AccountId::random(),
        sid: "sid-abcdef".to_string(),
        kind: OlmMessageKind::PreKey,
        payload: b"opaque olm bytes".to_vec(),
    }
}

fn all_variants() -> Vec<Frame> {
    let account = AccountId::random();
    vec![
        Frame::Register(Registration {
            account_id: account,
            ed25519_pub: [1u8; 32],
            curve25519_pub: [2u8; 32],
            kdf_salt: [3u8; 16],
            kdf_params: KdfParams {
                m_cost: 19_456,
                t_cost: 2,
                p_cost: 1,
            },
        }),
        Frame::RegisterAck {
            account_id: account,
        },
        Frame::ChallengeRequest {
            account_id: account,
        },
        Frame::Challenge { nonce: [7u8; 32] },
        Frame::Login {
            account_id: account,
            nonce: [6u8; 32],
            signature: Signature::from_bytes([9u8; 64]),
        },
        Frame::LoginAck {
            account_id: account,
        },
        Frame::UploadPreKeys {
            prekeys: vec![PreKeyUpload {
                key_id: "key-1".to_string(),
                public_key: [4u8; 32],
            }],
        },
        Frame::UploadPreKeysAck { stored: 1 },
        Frame::FetchPreKey {
            account_id: account,
        },
        Frame::PreKeyBundle(PreKeyBundle {
            account_id: account,
            ed25519_pub: [1u8; 32],
            curve25519_pub: [2u8; 32],
            one_time_key_id: "key-1".to_string(),
            one_time_key: [5u8; 32],
        }),
        Frame::Send(sample_envelope()),
        Frame::Deliver {
            msg_id: "42-0".to_string(),
            envelope: sample_envelope(),
        },
        Frame::SendAck {
            msg_id: "42-0".to_string(),
        },
        Frame::DeliverAck {
            msg_id: "42-0".to_string(),
        },
        Frame::Error {
            code: ErrorCode::BadSignature,
            detail: "nope".to_string(),
        },
    ]
}

#[test]
fn every_variant_roundtrips() {
    for frame in all_variants() {
        let bytes = encode(&frame).unwrap();
        assert_eq!(decode(&bytes).unwrap(), frame);
    }
}

#[test]
fn empty_and_truncated_input_are_rejected() {
    assert!(decode(&[]).is_err());
    let bytes = encode(&Frame::Challenge { nonce: [7u8; 32] }).unwrap();
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = encode(&Frame::ChallengeRequest {
        account_id: AccountId::random(),
    })
    .unwrap();
    bytes.push(0);
    assert!(decode(&bytes).is_err());
}

#[test]
fn unknown_variant_is_rejected() {
    // postcard encodes enum tags as varints; 99 is beyond the current variant count.
    assert!(decode(&[99]).is_err());
}

#[test]
fn oversized_payload_is_rejected_at_encode() {
    let mut message = sample_envelope();
    message.payload = vec![0u8; sme_proto::MAX_ENVELOPE_PAYLOAD + 1];
    assert!(encode(&Frame::Send(message)).is_err());
}

#[test]
fn oversized_frame_is_rejected_at_decode() {
    let bytes = vec![0u8; sme_proto::MAX_FRAME_BYTES + 1];
    assert!(decode(&bytes).is_err());
}

#[test]
fn envelope_roundtrip_and_limits() {
    let envelope = sample_envelope();
    let bytes = encode_envelope(&envelope).unwrap();
    assert_eq!(decode_envelope(&bytes).unwrap(), envelope);

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_envelope(&trailing).is_err());
}

#[test]
fn invalid_kdf_params_are_rejected() {
    let frame = Frame::Register(Registration {
        account_id: AccountId::random(),
        ed25519_pub: [1u8; 32],
        curve25519_pub: [2u8; 32],
        kdf_salt: [3u8; 16],
        kdf_params: KdfParams {
            m_cost: 0,
            t_cost: 2,
            p_cost: 1,
        },
    });
    assert!(encode(&frame).is_err());
}
