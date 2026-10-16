//! Image compression and metadata stripping (EXIF/GPS/ICC): pure byte transforms, no IO, no crypto (plan.md §6, I12).
//!
//! M0 skeleton only; the compression pipeline lands in M5 with only the `image` jpeg/png/webp/gif features enabled.
//! This crate forbids file / network / process APIs (I2 gate).
