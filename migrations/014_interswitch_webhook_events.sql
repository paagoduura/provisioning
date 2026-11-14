CREATE TABLE IF NOT EXISTS interswitch_webhook_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) BETWEEN 1 AND 256),
    session_id TEXT NOT NULL REFERENCES provisioning_sessions(id),
    payload_hash BYTEA NOT NULL CHECK (octet_length(payload_hash) = 32),
    received_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT interswitch_webhook_events_session_payload_unique UNIQUE (session_id, payload_hash)
);

CREATE INDEX IF NOT EXISTS interswitch_webhook_events_received_idx
    ON interswitch_webhook_events (received_at);

ALTER TABLE interswitch_webhook_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON interswitch_webhook_events FROM PUBLIC;
