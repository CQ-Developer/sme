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

/// Maximum total bytes of buffered image payloads (plan.md §8).
/// Images are capped at 1MB each, so this budget is what actually bounds
/// memory when a conversation contains many pictures.
pub const ATTACHMENT_BYTES_LIMIT: usize = 8 * 1024 * 1024;

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

impl MessageBuffer<ReceivedMessage> {
    /// Push a decrypted message under both memory caps.
    ///
    /// The entry cap drops the oldest message first. If the remaining image payloads
    /// exceed [`ATTACHMENT_BYTES_LIMIT`], the oldest images are removed until the
    /// budget fits; text messages are never evicted by the byte budget.
    ///
    /// Returns the number of images evicted by the byte budget (0 when the entry cap
    /// was the only limit that applied).
    pub fn push_received(&mut self, message: ReceivedMessage) -> usize {
        if self.items.len() == MESSAGE_BUFFER_LIMIT {
            self.items.pop_front();
        }
        self.items.push_back(message);

        let mut dropped_images = 0;
        while self.image_bytes() > ATTACHMENT_BYTES_LIMIT {
            let Some(index) = self
                .items
                .iter()
                .position(|item| item.body.image_bytes_len().is_some())
            else {
                break;
            };
            self.items.remove(index);
            dropped_images += 1;
        }
        dropped_images
    }

    /// Total size of image payloads currently buffered.
    pub fn image_bytes(&self) -> usize {
        self.items
            .iter()
            .filter_map(|item| item.body.image_bytes_len())
            .sum()
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

    fn image_message(bytes: usize) -> ReceivedMessage {
        ReceivedMessage {
            from: sme_proto::AccountId::random(),
            body: sme_proto::MessageBody::Image {
                width: 1,
                height: 1,
                bytes: vec![0xAB; bytes],
            },
        }
    }

    fn text_message(text: &str) -> ReceivedMessage {
        ReceivedMessage {
            from: sme_proto::AccountId::random(),
            body: sme_proto::MessageBody::text(text).unwrap(),
        }
    }

    #[test]
    fn attachment_budget_evicts_the_oldest_image_but_keeps_text() {
        const IMAGE_BYTES: usize = 1_000_000;
        let mut buffer = MessageBuffer::new();

        for _ in 0..8 {
            assert_eq!(buffer.push_received(image_message(IMAGE_BYTES)), 0);
        }
        assert_eq!(buffer.push_received(text_message("keep me")), 0);

        assert_eq!(buffer.push_received(image_message(IMAGE_BYTES)), 1);
        assert_eq!(buffer.image_bytes(), 8 * IMAGE_BYTES);
        assert!(buffer.image_bytes() <= ATTACHMENT_BYTES_LIMIT);
        assert_eq!(buffer.len(), 9, "one image was evicted, the text stayed");
        assert!(
            buffer
                .iter()
                .any(|message| message.text() == Some("keep me"))
        );
        assert_eq!(
            buffer
                .iter()
                .filter(|message| message.body().image_bytes_len().is_some())
                .count(),
            8
        );
    }

    #[test]
    fn attachment_budget_never_evicts_text() {
        const IMAGE_BYTES: usize = 1_000_000;
        let mut buffer = MessageBuffer::new();
        buffer.push_received(text_message("keep me"));

        for _ in 0..9 {
            buffer.push_received(image_message(IMAGE_BYTES));
        }
        let dropped = buffer.push_received(image_message(IMAGE_BYTES));

        assert_eq!(dropped, 1);
        assert_eq!(buffer.image_bytes(), 8 * IMAGE_BYTES);
        assert!(buffer.image_bytes() <= ATTACHMENT_BYTES_LIMIT);
        assert!(
            buffer
                .iter()
                .any(|message| message.text() == Some("keep me"))
        );
    }

    #[test]
    fn push_received_still_enforces_the_entry_cap() {
        let mut buffer = MessageBuffer::new();
        for index in 0..(MESSAGE_BUFFER_LIMIT + 3) {
            buffer.push_received(text_message(&format!("m{index}")));
        }

        assert_eq!(buffer.len(), MESSAGE_BUFFER_LIMIT);
        assert_eq!(buffer.oldest().unwrap().text(), Some("m3"));
        assert_eq!(
            buffer.newest().unwrap().text(),
            Some(format!("m{}", MESSAGE_BUFFER_LIMIT + 2).as_str())
        );
    }
}
