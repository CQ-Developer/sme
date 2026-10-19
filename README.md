# sme

端到端加密一对一聊天：**消息零落盘**（客户端与服务端都不保存任何聊天内容），密钥与用户信息以口令派生的 KEK 加密持久化。目标是：服务端、客户端磁盘与备份里都搜不到聊天内容。

## 文档

| 文档 | 内容 |
| --- | --- |
| [plan.md](plan.md) | 决策记录 D1–D26、不变式 I1–I12、模块划分与里程碑 |
| [docs/INFRA.md](docs/INFRA.md) | Postgres 18.6 / Valkey 9.1.2 / Caddy 规格、键空间与配额 |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | 安全目标 G1–G10、对手 A1–A9、残余风险 R1–R14 |

## 开发

```bash
cargo test --workspace          # 含 I3（内存缓冲 ≤10 条）与 I11（keystore 不含明文）
python3 scripts/ci/run_gates.py # I1 字段名 / I2 核心禁词 / Valkey 禁持久化，含注入自检
```

服务端与端到端集成测试需要真实 Postgres 与 Docker（测试会自动起临时 Valkey 容器）：

```bash
docker run --rm -d --name sme-pg-test \
  -e POSTGRES_USER=sme -e POSTGRES_PASSWORD=sme -e POSTGRES_DB=sme \
  -p 127.0.0.1:5433:5432 postgres:18.6-alpine
DATABASE_URL=postgres://sme:sme@127.0.0.1:5433/sme cargo test --workspace
```

本地基础设施（需要 Docker）：

```bash
cp .env.example .env            # 填 SME_HMAC_KEY 与 POSTGRES_PASSWORD
docker compose up -d postgres valkey caddy
```

参考客户端（TUI，文本 + 图片预览）：

```bash
cargo run -p sme-client-tui -- ws://127.0.0.1:8080/ws
# Enter 登录 / /peer <账号> 选对端 / Ctrl+S 另存当前图片 / Ctrl+X 紧急擦除并删除本地数据
```

图片通过 `ratatui-image` 渲染：Kitty / iTerm2 / Sixel 走图形协议，探测失败或 tmux/ssh 穿透失败时自动回退 unicode halfblocks。接收端解码前会再次校验 JPEG 格式、实际尺寸与协议声明的尺寸一致（防解压炸弹）。图片只是内存中的消息，不写应用目录；唯一的落盘出口是 `Ctrl+S`（用户输入路径，拒绝应用数据目录与系统临时目录，且不覆盖已有文件）。内存中最多保留 10 条消息、图片合计 ≤8MB；超预算时先丢弃最旧图片并提示「ask the peer to resend」。`cargo test -p sme-client-tui` 覆盖另存为路径规则，`cargo test -p sme-client-core` 覆盖预算淘汰。

### 桌面三平台构建

| 平台 | 命令 | 依赖 / 限制 |
| --- | --- | --- |
| Linux（已在本仓库验证） | `cargo build -p sme-client-tui` | 只需 Rust 工具链；`ratatui-image` 已关闭默认 `chafa-*`，不需要本地 libchafa 或 pkg-config |
| macOS | `xcode-select --install` 后 `cargo build -p sme-client-tui` | 需要 macOS + Xcode Command Line Tools；**无法从 Linux 交叉编译**（缺 SDK 与链接器），必须在 macOS 上执行 |
| Windows | 安装 VS Build Tools（MSVC）后 `cargo build -p sme-client-tui` | 需要 MSVC 工具链（`stable-x86_64-pc-windows-msvc`）；从 Linux 交叉编译还需 Windows target 的 std 与 MSVC/MinGW 链接器，本仓库未配置 |

CI 的 `desktop` 矩阵在 ubuntu / macOS / Windows 上执行 `cargo build -p sme-client-tui` 与 `cargo test -p sme-client-tui`；本地无法从 Linux 交叉验证的 macOS/Windows 构建由该矩阵覆盖。

三平台的运行时差异只涉及数据目录（macOS `~/Library/Application Support/sme`、Windows `%APPDATA%\sme`、Linux `$XDG_DATA_HOME/sme`）与终端图形协议支持；消息缓冲与预算逻辑完全共用同一份 `sme-client-core`。

移动端绑定（需要 Xcode / Android 工具链才能编译，生成不需要）：

```bash
bash scripts/ci/gen-bindings.sh            # 输出到 target/bindings/{swift,kotlin}
```
