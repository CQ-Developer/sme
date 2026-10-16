#!/usr/bin/env python3
"""I2 门禁：核心 crate 源码里不得出现文件 / 网络 / 进程 / 环境 API。

扫描范围：crates/sme-crypto、crates/sme-media、crates/sme-proto、crates/sme-client-core。
命中即退出码 1（CI 失败）。这是「消息零落盘」的第一道防线，第二道在运行时（I4/I11）。

用法：check_core_io.py [仓库根目录]
"""

from __future__ import annotations

import sys
from pathlib import Path

CORE_CRATES = ("sme-crypto", "sme-media", "sme-proto", "sme-client-core")

# 刻意包含 tokio 等价物与常见别名：只过滤完整路径不够。
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
