//! 故意违规的 I2 反例：门禁必须挡住 `std::fs`。
//! 该文件不在真正的 workspace 里，只被 scripts/ci/run_gates.py 扫描。

pub fn leak() {
    let _ = std::fs::read("/etc/hostname");
}
