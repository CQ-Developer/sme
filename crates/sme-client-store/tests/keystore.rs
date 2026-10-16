//! I11: the on-disk keystore must be ciphertext and must not contain identity private keys or message bytes.

mod common;

use std::fs;

use common::TestDir;
use sme_client_store::Keystore;

const PASSWORD: &[u8] = b"correct horse battery staple";
const IDENTITY_CANARY: [u8; 32] = [0x5a; 32];
const MESSAGE_CANARY: &[u8] = b"CANARY-sme-msg-7f3a91d2-must-not-reach-disk";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn keystore_file_is_ciphertext_only() {
    let dir = TestDir::new("keystore");
    let path = dir.join("keystore.bin");

    let mut keystore = Keystore::create(&path, PASSWORD).unwrap();
    keystore.put("identity.ed25519.secret", IDENTITY_CANARY);
    keystore.put("canary", MESSAGE_CANARY);
    keystore.save().unwrap();

    let on_disk = fs::read(&path).unwrap();
    assert!(!contains(&on_disk, &IDENTITY_CANARY), "身份私钥明文落盘了");
    assert!(!contains(&on_disk, MESSAGE_CANARY), "消息字节落盘了");

    let reopened = Keystore::open(&path, PASSWORD).unwrap();
    assert_eq!(
        reopened.get("identity.ed25519.secret"),
        Some(&IDENTITY_CANARY[..])
    );
    assert_eq!(reopened.get("canary"), Some(MESSAGE_CANARY));
    assert_eq!(reopened.len(), 2);

    assert!(
        Keystore::open(&path, b"wrong password").is_err(),
        "错误口令必须打不开"
    );
}

#[cfg(unix)]
#[test]
fn keystore_file_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TestDir::new("keystore-mode");
    let path = dir.join("keystore.bin");

    let mut keystore = Keystore::create(&path, PASSWORD).unwrap();
    keystore.put("identity", b"secret".as_slice());
    keystore.save().unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "keystore 权限必须是 0600，实际 {mode:o}");
}
