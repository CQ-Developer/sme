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
                violations.append(f"{source}: cannot read: {error}")
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                for token in FORBIDDEN:
                    if token in line:
                        violations.append(f"{source.relative_to(root)}:{line_number}: matches {token!r}")
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    violations = scan(root)
    if violations:
        print("I2 gate failed: core crates use a forbidden IO / network / process API")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print(f"I2 gate passed: {', '.join(CORE_CRATES)} use no forbidden APIs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
