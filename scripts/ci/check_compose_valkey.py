#!/usr/bin/env python3
"""门禁③：docker-compose.yml 中的 Valkey 必须禁用一切持久化。

断言（docs/INFRA.md §5、§9）：
  - valkey 服务不挂任何卷；
  - 数据目录 /data 挂 tmpfs；
  - 启动参数含 --save ""、--appendonly no、--maxmemory 1gb、--maxmemory-policy noeviction、--dir /data。

Valkey 一旦落盘，「消息零落盘」直接失效。除本 lint 外还有启动自检（I7）与 tmpfs 两道防线。

用法：check_compose_valkey.py [compose 文件路径]
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
        return [f"无法解析 {compose_path}: {error}"]

    services = (document or {}).get("services") or {}
    valkey = services.get("valkey")
    if not isinstance(valkey, dict):
        return [f"{compose_path}: 找不到 services.valkey"]

    problems: list[str] = []
    if valkey.get("volumes"):
        problems.append("valkey 挂载了 volumes（必须只存在于 tmpfs）")

    tmpfs = valkey.get("tmpfs") or []
    if isinstance(tmpfs, str):
        tmpfs = [tmpfs]
    if not any(str(entry).startswith("/data") for entry in tmpfs):
        problems.append("valkey 缺少 tmpfs /data")

    command = valkey.get("command") or ""
    if isinstance(command, list):
        command = " ".join(str(part) for part in command)
    command = str(command)

    required = (
        (r'--save\s+(""|\'\')', '--save ""（关闭 RDB 快照）'),
        (r"--appendonly\s+no\b", "--appendonly no（关闭 AOF）"),
        (r"--maxmemory\s+1gb\b", "--maxmemory 1gb"),
        (r"--maxmemory-policy\s+noeviction\b", "--maxmemory-policy noeviction"),
        (r"--dir\s+/data\b", "--dir /data"),
    )
    for pattern, description in required:
        if not re.search(pattern, command):
            problems.append(f"valkey 启动参数缺少 {description}")

    return problems


def main(argv: list[str]) -> int:
    default = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    compose_path = Path(argv[1]).resolve() if len(argv) > 1 else default
    problems = check(compose_path)
    if problems:
        print(f"Valkey 禁持久化门禁失败：{compose_path}")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(f"Valkey 禁持久化门禁通过：{compose_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
