#!/usr/bin/env bash
# Generate Swift and Kotlin bindings from the sme-ffi cdylib (D4b).
#
# Compiling the generated bindings needs Xcode / Android toolchains, but
# generating them is pure Rust and runs in CI.
#
# Usage: scripts/ci/gen-bindings.sh [output-dir]

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="${1:-$repo_root/target/bindings}"

cd "$repo_root"
cargo build -p sme-ffi

library="$repo_root/target/debug/libsme_ffi.so"
for language in swift kotlin; do
    cargo run -q -p sme-ffi --features cli --bin uniffi-bindgen -- \
        generate --no-format \
        --library "$library" \
        --language "$language" \
        --out-dir "$out_dir/$language"
    echo "generated $language bindings in $out_dir/$language"
done
