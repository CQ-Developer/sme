//! I6：消息与会话相关类型必须声明为「drop 时零化」。
//!
//! 内存擦除的完整证明超出单元测试能力（`mlock`/core dump 是尽力项），
//! 这里锁住的是类型层面的契约：任何持有明文的类型都必须带 `ZeroizeOnDrop`。

use sme_client_core::ReceivedMessage;
use zeroize::ZeroizeOnDrop;

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn message_types_wipe_on_drop() {
    assert_zeroize_on_drop::<ReceivedMessage>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
}
