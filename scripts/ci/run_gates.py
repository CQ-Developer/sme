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
    ("I2 core forbidden APIs (positive)", ["check_core_io.py"], 0),
    (
        "I2 core forbidden APIs (injected std::fs must be blocked)",
        ["check_core_io.py", str(FIXTURES / "bad_core_io")],
        1,
    ),
    ("I1 chat-content column names (positive)", ["check_message_columns.py"], 0),
    (
        "I1 chat-content column names (injected payload column must be blocked)",
        ["check_message_columns.py", str(FIXTURES / "bad_message_column")],
        1,
    ),
    ("Valkey no-persistence (positive)", ["check_compose_valkey.py"], 0),
    (
        "Valkey no-persistence (injected appendonly yes must be blocked)",
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
        print(f"[{status}] {name} (exit={completed.returncode}, expected {expected})")
        output = (completed.stdout + completed.stderr).strip()
        for line in output.splitlines():
            print(f"        {line}")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"{failures} gate cases did not match expectations")
        return 1
    print("All three gates passed and every injected violation was blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
