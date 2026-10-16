根据我们上一轮的讨论，以及相关官方文档与技术资料的核实，修正后的总结摘要如下。

---

## 总结摘要：sqlx 查询方案 A vs B

### 一、核心修正点

上一轮讨论中把 `sqlx-cli` 的安装依赖方向说反了。**正确的归属是：方案 B（编译期宏 `query!`）才必须安装 `sqlx-cli`**，因为离线缓存 `.sqlx/` 的生成命令 `cargo sqlx prepare` 来自 `sqlx-cli`。方案 A 虽然也推荐安装 `sqlx-cli` 用于创建迁移文件（`sqlx migrate add`），但并非强制——可以手动在 `migrations/` 目录下创建带时间戳前缀的 `.sql` 文件来绕过 CLI。

### 二、两条方案的本质区别

**方案 A（运行时查询 + `migrate!`）**

使用 `sqlx::query_as` 在运行时构建查询。SQL 作为字符串在运行时解析，没有编译期校验，列名拼写错误或类型不匹配只会在运行时暴露。`sqlx::migrate!` 宏在编译期将 `migrations/` 目录下的 SQL 文件嵌入二进制，展开为一个静态的 `Migrator` 实例，与 `query!` 宏是独立的两套功能。迁移文件推荐用 `sqlx migrate add <name>` 创建，会生成 `migrations/<timestamp>-<name>.sql` 格式的文件，但也可以手动创建时间戳前缀文件来绕过 CLI。

**方案 B（编译期宏 `query!` + `.sqlx/` 离线缓存）**

使用 `query!` / `query_as!` 宏，在编译时连接真实数据库（或读取 `.sqlx/` 离线缓存），验证 SQL 语法和列类型是否与当前 schema 匹配。要实现在 CI 中不连库编译，标准流程是：先 `cargo install sqlx-cli`，在有 `DATABASE_URL` 的环境下运行 `cargo sqlx prepare` 生成 `.sqlx/` 目录，然后提交到版本控制；编译时设置 `SQLX_OFFLINE=true` 让宏回退到离线缓存。

### 三、关键对比表

| 维度 | 方案 A（运行时查询） | 方案 B（编译期宏） |
|---|---|---|
| **SQL 编译期校验** | 无 | 有 |
| **必须安装 `sqlx-cli`** | 否（推荐但不强制） | **是**（用于 `cargo sqlx prepare`） |
| **CI 需要连库** | 不需要 | 不需要，但需提交并校验 `.sqlx/` |
| **改查询后的工作流** | 直接改 Rust 代码 | 改代码 → 跑 `prepare` → 提交 `.sqlx/` diff |
| **迁移嵌入方式** | `migrate!` 编译期嵌入 | 同样用 `migrate!`，与 `query!` 无关 |
| **适用场景** | schema 快速变动、查询数量不大 | schema 稳定、看重编译期安全信号 |

### 四、离线缓存工作流详解（方案 B 特有）

`.sqlx/` 缓存的生成依赖三步流程。首先执行 `cargo sqlx prepare`，该命令会调用 `cargo check` 并在过程中捕获宏展开产生的查询元数据；CLI 随后将元数据从临时目录移动到 `.sqlx/` 目录持久化存储。其次将 `.sqlx/` 目录提交到版本控制，此后编译不再需要活跃数据库连接。最后在 CI 中运行 `cargo sqlx prepare --check` 来校验缓存是否与当前代码和 schema 保持一致，缓存过期时该命令会以非零退出码退出。此外需要注意，`DATABASE_URL` 环境变量的存在会优先生效，要强制离线模式需设置 `SQLX_OFFLINE=true`。

### 五、迁移文件创建与重编译触发

`sqlx migrate add <name>` 创建的文件遵循 `<timestamp>-<name>.sql` 格式，时间戳为 `YYYYMMDDHHMMSS` 的 UTC 时间。如果需要回滚脚本，使用 `-r` 标志会同时生成 `.up.sql` 和 `.down.sql` 两个文件。

使用 `migrate!` 宏时有一个容易踩坑的地方：如果只添加新的迁移文件而不修改任何 Rust 源文件，`cargo build` 可能不会重新触发宏展开，导致新迁移不被嵌入。稳定 Rust 下的解决方案是在项目中创建一个 `build.rs`，内容为 `println!("cargo:rerun-if-changed=migrations");`，可以用 `sqlx migrate build-script` 自动生成。

### 六、最终选择框架

选择取决于团队愿意为**编译期 SQL 安全**支付多少**缓存维护成本**。如果 M2 阶段查询数量不大、认证相关 schema 还在快速迭代，方案 A 的迭代速度优势更明显；如果 schema 已经稳定，且团队认为“改表结构时编译直接报错”这个信号的价值超过 `.sqlx/` 的维护开销，方案 B 的长期收益才值得投入。

---

## 信息源

1. **sqlx 官方文档：`migrate!` 宏** — https://docs.rs/sqlx/0.5.10/sqlx/macro.migrate.html
   涵盖 `migrate!` 的编译期嵌入机制、重编译触发问题的完整说明。

2. **sqlx-cli 官方文档（0.7.0）** — https://docs.rs/crate/sqlx-cli/0.7.0
   涵盖 CLI 安装、迁移管理、离线模式两步流程、`prepare --check` 的 CI 用途。

3. **sqlx-cli crates.io 页面（v0.8.6）** — https://crates.io/crates/sqlx-cli
   包含最新版本的安装命令和离线模式说明。

4. **Stack Overflow：`query_as` 与 `query_as!` 的区别** — https://stackoverflow.com/questions/61576582/
   直接回答了两者运行时解析 vs 编译期校验的核心差异。

5. **DeepWiki：Offline Mode & sqlx prepare** — https://deepwiki.com/transact-rs/sqlx/4.2-offline-mode-and-sqlx-prepare
   详细拆解了 `cargo sqlx prepare` 的内部管线：workspace 发现、定向重编译、元数据持久化。

6. **Rust SQLx 编译期检查与离线构建指南** — https://skills.rest/skill/rust-sqlx
   概述了编译期查询、运行时查询、迁移管理、离线准备四类核心能力的适用场景。

7. **sqlx-cli Migration Commands（DeepWiki）** — https://deepwiki.com/transact-rs/sqlx/
   涵盖 `migrate add` 的时间戳版本策略和 `--sequential` 选项。