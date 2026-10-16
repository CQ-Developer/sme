//! Session management, Olm session ownership, replay window and in-memory message buffer (plan.md §5, §8).
//!
//! This crate forbids all file / network / process APIs (I2 gate): [`Client`] only takes and returns
//! [`sme_proto::Frame`] and [`Action`]; the caller owns transport (`sme-client-net`)
//! and persistence (`sme-client-store`).
//! Plaintext lives only in [`MessageBuffer`], capped at [`MESSAGE_BUFFER_LIMIT`] entries and never written to disk (I3, I11).

mod client;

use std::collections::VecDeque;

pub use client::{Action, Client, CoreError, ReceivedMessage};

/// Maximum number of plaintext messages kept in memory (plan.md §8).
pub const MESSAGE_BUFFER_LIMIT: usize = 10;

/// Ring buffer keeping the latest [`MESSAGE_BUFFER_LIMIT`] entries in arrival order; older ones are dropped.
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

    /// Append a message; drops the oldest one past the cap.
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

    /// Clear the buffer; each message is `zeroize`d on drop (I6).
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Iterate in arrival order (oldest -> newest).
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// The oldest entry (next to be dropped).
    pub fn oldest(&self) -> Option<&T> {
        self.items.front()
    }

    /// The newest entry.
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

    /// I3: after 100 pushes only the latest 10 remain, in order.
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
