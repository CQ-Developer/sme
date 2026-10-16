-- The single business table: account, public keys, client-generated password salt and KDF params (docs/INFRA.md §3).
-- Never add columns related to chat history; the I1 gate (scripts/ci/check_message_columns.py) scans this directory.
CREATE TABLE accounts (
    account_id     TEXT        PRIMARY KEY,   -- 128-bit random, 26 base32 chars (D16)
    ed25519_pub    BYTEA       NOT NULL,      -- 32-byte identity public key
    curve25519_pub BYTEA       NOT NULL,      -- 32-byte Olm identity public key
    kdf_salt       BYTEA       NOT NULL,      -- 16 bytes, client-generated (the server cannot pick a weak salt)
    kdf_params     JSONB       NOT NULL,      -- {alg:"argon2id", v:19, m_cost, t_cost, p_cost}
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
