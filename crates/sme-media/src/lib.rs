//! 图片压缩与元数据剥离（EXIF/GPS/ICC）：纯字节变换，无 IO、无密码学（plan.md §6、I12）。
//!
//! M0 只有骨架；压缩链路在 M5 落地，届时只开 `image` 的 jpeg/png/webp/gif 特性。
//! 本 crate 禁止文件 / 网络 / 进程 API（I2 门禁）。
