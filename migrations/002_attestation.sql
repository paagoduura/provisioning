CREATE TABLE IF NOT EXISTS attestation_challenges (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES provisioning_sessions(id),
    challenge_value TEXT NOT NULL,
    challenge_hash BYTEA NOT NULL UNIQUE,
    request_hash BYTEA NOT NULL,
    request_hash_value TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS attestation_challenges_session_idx ON attestation_challenges (session_id);
CREATE INDEX IF NOT EXISTS attestation_challenges_expiry_idx ON attestation_challenges (expires_at);

CREATE TABLE IF NOT EXISTS device_attestations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES provisioning_sessions(id),
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    counter BIGINT NOT NULL CHECK (counter >= 0),
    trust_level TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (session_id, provider, key_id)
);

REVOKE ALL ON attestation_challenges, device_attestations FROM PUBLIC;
