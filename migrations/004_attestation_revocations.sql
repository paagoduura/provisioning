CREATE TABLE IF NOT EXISTS device_key_revocations (
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, key_id)
);
REVOKE ALL ON device_key_revocations FROM PUBLIC;
