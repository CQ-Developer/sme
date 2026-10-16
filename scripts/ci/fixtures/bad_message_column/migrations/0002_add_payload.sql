-- I1 反例：门禁必须挡住 payload 列。
ALTER TABLE accounts ADD COLUMN payload BYTEA;
