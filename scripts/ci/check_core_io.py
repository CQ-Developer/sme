#!/usr/bin/env python3
"""I2 gate: core crates must not use file / network / process / environment APIs.

Scanned crates: sme-crypto, sme-media, sme-proto, sme-client-core.
A hit exits with code 1 (CI failure). This is the first line of defence for
"no message ever hits disk"; the runtime line is I4/I11.

Usage: check_core_io.py [repo root]
"""

from __future__ import annotations

import sys
from pathlib import Path

CORE_CRATES = ("sme-crypto", "sme-media", "sme-proto", "sme-client-core")

# Deliberately include tokio equivalents and common aliases: filtering full paths alone is not enough.
FORBIDDEN = (
    "std::fs",
    "std::net",
    "std::process",
    "std::env",
    "tokio::fs",
    "tokio::net",
    "tokio::process",
    "File::",
    "OpenOptions",
    "TcpStream",
    "TcpListener",
    "UdpSocket",
    "Command::new",
)


def scan(root: Path) -> list[str]:
    violations: list[str] = []
    for crate in CORE_CRATES:
        for source in sorted((root / "crates" / crate).rglob("*.rs")):
            try:
                text = source.read_text(encoding="utf-8")
            except OSError as error:
                violations.append(f"{source}: 无法读取: {error}")
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                for token in FORBIDDEN:
                    if token in line:
                        violations.append(f"{source.relative_to(root)}:{line_number}: 命中 {token!r}")
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    violations = scan(root)
    if violations:
        print("I2 门禁失败：核心 crate 出现了禁止的 IO / 网络 / 进程 API")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print(f"I2 门禁通过：{', '.join(CORE_CRATES)} 无禁止 API")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
