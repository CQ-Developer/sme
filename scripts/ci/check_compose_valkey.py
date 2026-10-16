#!/usr/bin/env python3
"""Gate 3: Valkey in docker-compose.yml must have all persistence disabled.

Assertions (docs/INFRA.md §5, §9):
  - the valkey service mounts no volumes;
  - /data is a tmpfs;
  - the command contains --save "", --appendonly no, --maxmemory 1gb,
    --maxmemory-policy noeviction and --dir /data.

Valkey writing to disk breaks "no message ever hits disk" outright. Besides this
lint there is the startup self-check (I7) and the tmpfs as a second line of defence.

Usage: check_compose_valkey.py [compose file path]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


def check(compose_path: Path) -> list[str]:
    try:
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        return [f"cannot parse {compose_path}: {error}"]

    services = (document or {}).get("services") or {}
    valkey = services.get("valkey")
    if not isinstance(valkey, dict):
        return [f"{compose_path}: services.valkey not found"]

    problems: list[str] = []
    if valkey.get("volumes"):
        problems.append("valkey mounts volumes (it must live on tmpfs only)")

    tmpfs = valkey.get("tmpfs") or []
    if isinstance(tmpfs, str):
        tmpfs = [tmpfs]
    if not any(str(entry).startswith("/data") for entry in tmpfs):
        problems.append("valkey is missing the tmpfs /data mount")

    command = valkey.get("command") or ""
    if isinstance(command, list):
        command = " ".join(str(part) for part in command)
    command = str(command)

    required = (
        (r'--save\s+(""|\'\')', '--save "" (RDB snapshots off)'),
        (r"--appendonly\s+no\b", "--appendonly no (AOF off)"),
        (r"--maxmemory\s+1gb\b", "--maxmemory 1gb"),
        (r"--maxmemory-policy\s+noeviction\b", "--maxmemory-policy noeviction"),
        (r"--dir\s+/data\b", "--dir /data"),
    )
    for pattern, description in required:
        if not re.search(pattern, command):
            problems.append(f"valkey command is missing {description}")

    return problems


def main(argv: list[str]) -> int:
    default = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    compose_path = Path(argv[1]).resolve() if len(argv) > 1 else default
    problems = check(compose_path)
    if problems:
        print(f"Valkey no-persistence gate failed: {compose_path}")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(f"Valkey no-persistence gate passed: {compose_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
