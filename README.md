# sme

端到端加密一对一聊天：**消息零落盘**（客户端与服务端都不保存任何聊天内容），密钥与用户信息以口令派生的 KEK 加密持久化。目标是：服务端、客户端磁盘与备份里都搜不到聊天内容。

## 文档

| 文档 | 内容 |
| --- | --- |
| [plan.md](plan.md) | 决策记录 D1–D22、不变式 I1–I12、模块划分与里程碑 |
| [docs/INFRA.md](docs/INFRA.md) | Postgres 18.6 / Valkey 9.1.2 / Caddy 规格、键空间与配额 |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | 安全目标 G1–G10、对手 A1–A9、残余风险 R1–R14 |

## 开发（M0 骨架）

```bash
cargo test --workspace          # 含 I3（内存缓冲 ≤10 条）与 I11（keystore 不含明文）
python3 scripts/ci/run_gates.py # I1 字段名 / I2 核心禁词 / Valkey 禁持久化，含注入自检
```

服务端与端到端集成测试需要真实 Postgres：

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
