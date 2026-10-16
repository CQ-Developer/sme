//! Deliberate I2 counter-example: the gate must block `std::fs`.
//! Not part of the real workspace; scanned only by scripts/ci/run_gates.py.

pub fn leak() {
    let _ = std::fs::read("/etc/hostname");
}
