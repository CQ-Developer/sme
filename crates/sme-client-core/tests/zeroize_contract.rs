//! I6: message and session types must be declared zero-on-drop.
//!
//! Fully proving memory wiping is beyond unit tests (`mlock` / core dumps are best-effort),
//! This pins the type-level contract: every type holding plaintext must implement `ZeroizeOnDrop`.

use sme_client_core::ReceivedMessage;
use zeroize::ZeroizeOnDrop;

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn message_types_wipe_on_drop() {
    assert_zeroize_on_drop::<ReceivedMessage>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
}
