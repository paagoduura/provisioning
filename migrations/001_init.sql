CREATE TABLE IF NOT EXISTS provisioning_sessions (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    device_uid_hash BYTEA NOT NULL,
    device_model TEXT NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('nfc', 'ble')),
    state TEXT NOT NULL,
    correlation_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    failure_code TEXT
);

CREATE INDEX IF NOT EXISTS provisioning_sessions_device_idx ON provisioning_sessions (device_uid_hash);
CREATE INDEX IF NOT EXISTS provisioning_sessions_expiry_idx ON provisioning_sessions (expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id TEXT REFERENCES provisioning_sessions(id),
    event_type TEXT NOT NULL,
    result TEXT NOT NULL,
    reason_code TEXT,
    event_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_session_idx ON audit_events (session_id);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events (created_at);

REVOKE ALL ON provisioning_sessions, audit_events FROM PUBLIC;
