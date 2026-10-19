# 运行时审计（I9 与桌面终端）

本文记录两类无法完全放进 CI 的审计：**I9 全链路金丝雀**的手动全盘步骤，以及**桌面终端图形协议**的真机检查。自动化能覆盖的部分已经在测试里跑；这里只列需要人确认的边界。

## 1. I9 全链路金丝雀

### 1.1 自动化覆盖

测试：`crates/sme-client/tests/end_to_end.rs::i9_canary_never_reaches_app_dirs_database_or_queue`

```bash
docker run -d --rm --name sme-pg-test \
  -e POSTGRES_USER=sme -e POSTGRES_PASSWORD=sme -e POSTGRES_DB=sme \
  -p 127.0.0.1:5433:5432 postgres:18.6-alpine
DATABASE_URL=postgres://sme:sme@127.0.0.1:5433/sme \
  cargo test -p sme-client --test end_to_end i9_canary -- --nocapture
```

覆盖范围：

| 位置 | 断言 |
| --- | --- |
| 客户端 app 目录（keystore + config） | 文本金丝雀与图片字节都不出现；客户端退出/重启后仍不出现 |
| Postgres 全表（`accounts` + `_sqlx_migrations`） | `to_jsonb` 全行 dump 不含金丝雀 |
| Valkey 全键/值（含 Stream 的 `DUMP`） | 键名与值都不含金丝雀 |
| Valkey 容器日志 | 不含金丝雀 |
| Valkey 重启后 | 再 dump 仍不含金丝雀 |
| 服务端 stdout/stderr | 由 `sme-server/tests/invariants.rs` 的 **I5** 用同一类金丝雀覆盖 |

未自动化：整块磁盘、OS swap、core dump、备份系统。它们不属于应用自身的写操作（plan §11），只能按下面的发布前清单人工抽查。

### 1.2 发布前手动全盘抽查

1. 准备一台干净机器，记录唯一金丝雀，例如 `CANARY-MANUAL-<random>`。
2. 启动 `postgres` / `valkey` / 服务端，运行两个 TUI 客户端；发送包含金丝雀的文本与图片（图片可用 `sme-media` 样例图），完成收发后退出客户端。
3. 收集待扫描位置：
   - 客户端数据目录：Linux `~/.local/share/sme/`、macOS `~/Library/Application Support/sme/`、Windows `%APPDATA%\sme\`
   - 用户库 dump：`pg_dump --data-only "$DATABASE_URL" > /tmp/sme-db.sql`
   - 容器/服务日志：`docker compose logs > /tmp/sme-compose.log`
   - 应用日志与系统日志中与 `sme` / 服务端进程相关的部分
   - 应用临时目录（`/tmp`、`%TEMP%`、`$TMPDIR`）中本次运行期间新增的文件
   - 若启用了 core dump：`/var/lib/systemd/coredump`、`/cores` 等
4. 扫描（二进制也按文本搜索，避免漏掉裸字节）：

   ```bash
   grep -r --binary-files=text -n "CANARY-MANUAL-<random>" \
     ~/.local/share/sme /tmp/sme-db.sql /tmp/sme-compose.log /tmp 2>/dev/null
   ```

   期望：**零命中**。keystore 与 Valkey 中只会有 AEAD / Olm 密文，金丝雀明文不应出现。
5. 记录日期、平台、命令与结果到本文件的「1.3 记录」表。

### 1.3 记录

| 日期 | 平台 | 范围 | 结果 | 备注 |
| --- | --- | --- | --- | --- |
| 2026-10-19 | Linux/WSL2 | 自动化 I9 + I5 | 通过 | CI 与本地 `cargo test --workspace` |

## 2. 桌面终端图形协议

`ratatui-image` 会在运行时探测终端能力；探测失败、tmux/ssh 穿透失败时回退 unicode halfblocks。CI 只能验证编译与单测，**实际像素效果需要在真机终端确认**。

### 2.1 工具

```bash
cargo build -p sme-client-tui

# 1. 打印探测结果（协议、字体尺寸、capabilities）
./target/debug/sme-client-tui --terminal-probe

# 2. 不连服务端、不读 keystore，直接渲染一张生成图
./target/debug/sme-client-tui --image-demo
# Esc 或 Ctrl+C 退出（若启动瞬间按键被终端探测吞掉，再按一次即可）
```

`--terminal-probe` 的典型输出：

```text
protocol: Kitty
font-size: 10x20
capabilities: [...]
```

`protocol` 取值：`Kitty` / `Iterm2` / `Sixel` / `Halfblocks`。

### 2.2 预期与检查项

| 终端 | 预期协议 | 检查 |
| --- | --- | --- |
| Kitty | `Kitty` | 图片清晰、透明/背景正常；不产生临时文件；放大缩小窗口后比例保持 |
| iTerm2 | `Iterm2` | 同上 |
| WezTerm | `Iterm2` 或 `Kitty`（取决于能力） | 同上 |
| Windows Terminal（新版） | `Sixel`（已探测） | 图片清晰、缩放正常；若花屏则记录回退情况 |
| foot / Konsole / 其他 Sixel 终端 | `Sixel` | 颜色与缩放正常 |
| tmux（图形穿透未配置） | `Halfblocks` | 不崩溃、无花屏；图片以半块字符显示 |
| SSH 到远端 | 视终端而定，通常 `Halfblocks` | 不崩溃；Ctrl+S 另存为仍可用 |
| 无图形终端 / CI PTY | `Halfblocks` | 回退正常 |

所有终端都追加检查：

- `--image-demo` 中图片不被拉伸变形；窗口 resize 后仍保持比例。
- 在聊天中收到图片后，预览区显示正常；`Ctrl+S` 另存为写出的 JPEG 可被系统图片查看器打开。
- 退出（Esc / Ctrl+C）后 alternate screen 恢复，没有残留图像或光标异常。

### 2.3 记录

| 日期 | 平台 | 终端 | 探测协议 | 预览 | 备注 |
| --- | --- | --- | --- | --- | --- |
| 2026-10-19 | Linux/WSL2 | `script` PTY（xterm-256color） | `Halfblocks` | 回退正常 | 无图形协议；`--terminal-probe` 输出 Halfblocks |
| 2026-10-19 | Windows | Windows Terminal | `Sixel` | 待确认 | capabilities: `[Sixel, RectangularOps, CellSize(Some((10, 20)))]`；`--image-demo` 应显示 320×200 渐变+棋盘格，需终端截图确认 |
| | | Kitty | | | 待真机确认 |
| | | iTerm2 | | | 待真机确认 |
| | | tmux / ssh | | | 待真机确认 |


> 备注：`--image-demo` 渲染的是代码生成的 320×200 渐变 + 棋盘格测试图，不是任何浏览器页面。若截到的是其他窗口，说明截错窗口了；请直接截终端窗口本身。
