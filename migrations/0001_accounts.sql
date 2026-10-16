-- 唯一的业务表：账号、公钥、客户端生成的口令盐与 KDF 参数（docs/INFRA.md §3）。
-- 严禁加入任何聊天记录相关列；I1 门禁（scripts/ci/check_message_columns.py）会扫描本目录。
CREATE TABLE accounts (
    account_id     TEXT        PRIMARY KEY,   -- 128-bit 随机，base32 26 字符（D16）
    ed25519_pub    BYTEA       NOT NULL,      -- 32 字节，身份公钥
    curve25519_pub BYTEA       NOT NULL,      -- 32 字节，Olm 身份公钥
    kdf_salt       BYTEA       NOT NULL,      -- 16 字节，客户端生成（服务端无法挑弱盐）
    kdf_params     JSONB       NOT NULL,      -- {alg:"argon2id", v:19, m_cost, t_cost, p_cost}
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
