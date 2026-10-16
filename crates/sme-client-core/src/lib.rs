//! 会话管理、Olm 会话持有、重放窗口与内存消息缓冲（plan.md §5、§8）。
//!
//! 本 crate 禁止任何文件 / 网络 / 进程 API（I2 门禁）：[`Client`] 只进出
//! [`sme_proto::Frame`] 与 [`Action`]，由调用方负责传输（`sme-client-net`）
//! 与持久化（`sme-client-store`）。
//! 明文消息只存在于 [`MessageBuffer`] 中，上限 [`MESSAGE_BUFFER_LIMIT`] 条，永不落盘（I3、I11）。

mod client;

use std::collections::VecDeque;

pub use client::{Action, Client, CoreError, ReceivedMessage};

/// 内存中保留的明文消息条数上限（plan.md §8）。
pub const MESSAGE_BUFFER_LIMIT: usize = 10;

/// 按到达顺序保留最近 [`MESSAGE_BUFFER_LIMIT`] 条的环形缓冲；更早的被丢弃。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageBuffer<T> {
    items: VecDeque<T>,
}

impl<T> MessageBuffer<T> {
    pub fn new() -> Self {
        Self {
            items: VecDeque::with_capacity(MESSAGE_BUFFER_LIMIT),
        }
    }

    /// 追加一条消息；超出上限时丢弃最旧的一条。
    pub fn push(&mut self, item: T) {
        if self.items.len() == MESSAGE_BUFFER_LIMIT {
            self.items.pop_front();
        }
        self.items.push_back(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 清空缓冲；每条消息在 drop 时被 `zeroize`（I6）。
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// 按到达顺序遍历（旧 → 新）。
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// 最早的一条（下一条将被丢弃的消息）。
    pub fn oldest(&self) -> Option<&T> {
        self.items.front()
    }

    /// 最新的一条。
    pub fn newest(&self) -> Option<&T> {
        self.items.back()
    }
}

impl<T> Default for MessageBuffer<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T> IntoIterator for &'a MessageBuffer<T> {
    type Item = &'a T;
    type IntoIter = std::collections::vec_deque::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I3：写入 100 条后只保留最近 10 条，且顺序正确。
    #[test]
    fn keeps_only_the_latest_ten() {
        let mut buffer = MessageBuffer::new();
        for i in 0..100 {
            buffer.push(i);
        }

        assert_eq!(buffer.len(), MESSAGE_BUFFER_LIMIT);
        assert_eq!(buffer.oldest(), Some(&90));
        assert_eq!(buffer.newest(), Some(&99));

        let items: Vec<_> = buffer.iter().copied().collect();
        assert_eq!(items, (90..100).collect::<Vec<_>>());
    }

    #[test]
    fn empty_buffer_has_no_items() {
        let buffer: MessageBuffer<u8> = MessageBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.oldest(), None);
        assert_eq!(buffer.newest(), None);
    }

    #[test]
    fn clear_empties_the_buffer() {
        let mut buffer = MessageBuffer::new();
        buffer.push(1u8);
        buffer.push(2u8);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.oldest(), None);
    }
}
