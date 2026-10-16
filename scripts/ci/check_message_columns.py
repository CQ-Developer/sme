#!/usr/bin/env python3
"""I1 gate: migrations and SQL queries must not contain chat-content column names.

Rules:
  1. every .sql file under migrations/ is scanned in full;
  2. .rs files under crates/ only have string literals containing SQL keywords scanned,
     so ordinary identifiers and prose are not mis-flagged.

A hit fails CI. Schema assertions and DB-dump canaries (I1/I9) build on this in M3.

Implementation note for `.rs`: only fragments inside **string literals** that contain
an SQL keyword are scanned, so identifiers such as `Message::from()` / `into()` /
`values()` are not mistaken for SQL.

Usage: check_message_columns.py [repo root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN = ("message", "content", "body", "payload", "ciphertext", "envelope")

# Prefix matching: `message` must also catch `messages` / `message_id` so it cannot be bypassed.
FORBIDDEN_RE = re.compile(r"\b(" + "|".join(FORBIDDEN) + ")", re.IGNORECASE)

SQL_KEYWORD_RE = re.compile(
    r"\b(select|insert|update|delete|create|alter|drop|table)\b",
    re.IGNORECASE,
)

# Rust single-line string literals (escapes included); runtime query SQL lives inside them.
STRING_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def scan_sql_file(root: Path, source: Path) -> list[str]:
    violations: list[str] = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        match = FORBIDDEN_RE.search(line)
        if match:
            violations.append(f"{source.relative_to(root)}:{line_number}: 命中 {match.group(0)!r}")
    return violations


def scan_rust_file(root: Path, source: Path) -> list[str]:
    violations: list[str] = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        for literal in STRING_LITERAL_RE.finditer(line):
            content = literal.group(1)
            if not SQL_KEYWORD_RE.search(content):
                continue
            match = FORBIDDEN_RE.search(content)
            if match:
                violations.append(
                    f"{source.relative_to(root)}:{line_number}: 命中 {match.group(0)!r}"
                )
    return violations


def scan(root: Path) -> list[str]:
    violations: list[str] = []
    for source in sorted((root / "migrations").rglob("*.sql")):
        try:
            violations += scan_sql_file(root, source)
        except OSError as error:
            violations.append(f"{source}: 无法读取: {error}")
    for source in sorted((root / "crates").rglob("*.rs")):
        try:
            violations += scan_rust_file(root, source)
        except OSError as error:
            violations.append(f"{source}: 无法读取: {error}")
    return violations


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    violations = scan(root)
    if violations:
        print("I1 门禁失败：迁移或 SQL 查询里出现了聊天内容列名")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print("I1 门禁通过：migrations/ 与 .rs 内联 SQL 无聊天内容列名")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
