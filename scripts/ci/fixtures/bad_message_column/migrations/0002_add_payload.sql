-- I1 counter-example: the gate must block the payload column.
ALTER TABLE accounts ADD COLUMN payload BYTEA;
