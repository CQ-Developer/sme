#!/usr/bin/env python3
"""I1 门禁：迁移与 SQL 查询中不得出现聊天内容列名。

规则：
  1. migrations/ 下所有 .sql 文件整文件扫描；
  2. crates/ 下所有 .rs 文件只扫描「看起来是 SQL」的行（含 SELECT/INSERT/... 关键字），
     避免误伤普通注释与文档。

命中即 CI 失败。schema 断言与 DB dump 金丝雀（I1/I9）在 M3 叠加。

用法：check_message_columns.py [仓库根目录]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN = ("message", "content", "body", "payload", "ciphertext", "envelope")

# 用前缀匹配：`message` 也要命中 `messages` / `message_id`，防止绕过。
FORBIDDEN_RE = re.compile(r"\b(" + "|".join(FORBIDDEN) + ")", re.IGNORECASE)

SQL_RE = re.compile(
    r"\b(select|insert|update|delete|create|alter|drop|from|where|join|into|table|values)\b",
    re.IGNORECASE,
)


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
        if not SQL_RE.search(line):
            continue
        match = FORBIDDEN_RE.search(line)
        if match:
            violations.append(f"{source.relative_to(root)}:{line_number}: 命中 {match.group(0)!r}")
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
