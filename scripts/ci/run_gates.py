#!/usr/bin/env python3
"""Run the three CI gates and inject one violation into each to prove they fail.

Positive cases (current repo) must exit 0; negative cases (deliberate violations
under fixtures/) must exit non-zero. This is one of the M0 exit criteria: the
gates are not decoration.

Usage: run_gates.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CI_DIR = Path(__file__).resolve().parent
FIXTURES = CI_DIR / "fixtures"

CASES = (
    ("I2 核心禁词（正例）", ["check_core_io.py"], 0),
    (
        "I2 核心禁词（注入 std::fs 必须被挡）",
        ["check_core_io.py", str(FIXTURES / "bad_core_io")],
        1,
    ),
    ("I1 聊天内容列名（正例）", ["check_message_columns.py"], 0),
    (
        "I1 聊天内容列名（注入 payload 列必须被挡）",
        ["check_message_columns.py", str(FIXTURES / "bad_message_column")],
        1,
    ),
    ("Valkey 禁持久化（正例）", ["check_compose_valkey.py"], 0),
    (
        "Valkey 禁持久化（注入 appendonly yes 必须被挡）",
        ["check_compose_valkey.py", str(FIXTURES / "bad_compose_valkey.yml")],
        1,
    ),
)


def main() -> int:
    failures = 0
    for name, command, expected in CASES:
        completed = subprocess.run(
            [sys.executable, str(CI_DIR / command[0]), *command[1:]],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = completed.returncode == expected
        status = "OK  " if ok else "FAIL"
        print(f"[{status}] {name} (exit={completed.returncode}, 期望 {expected})")
        output = (completed.stdout + completed.stderr).strip()
        for line in output.splitlines():
            print(f"        {line}")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"{failures} 个门禁用例未达预期")
        return 1
    print("三条门禁全部通过，且注入的违规均被挡住")
    return 0


if __name__ == "__main__":
    sys.exit(main())
