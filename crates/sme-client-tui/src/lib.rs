//! ratatui reference client (M4): `main.rs` is the UI and [`session`] is the headless session layer.
//!
//! Plaintext exists only in `sme-client-core`'s 10-message buffer and in UI strings at render time,
//! This crate writes no message to disk (I4).

pub mod session;
