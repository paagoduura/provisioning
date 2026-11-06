CREATE TABLE IF NOT EXISTS apple_app_attest_keys (
    key_id TEXT PRIMARY KEY,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

REVOKE ALL ON apple_app_attest_keys FROM PUBLIC;
