ALTER TABLE provisioning_sessions
    ADD COLUMN IF NOT EXISTS device_id TEXT;

CREATE TABLE IF NOT EXISTS registered_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_uid_hash BYTEA NOT NULL UNIQUE,
    device_model TEXT NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('nfc', 'ble')),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'REPLACED', 'RETIRED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_id TEXT REFERENCES registered_devices(id),
    CHECK ((lifecycle_state = 'REVOKED') = (revoked_at IS NOT NULL) OR lifecycle_state <> 'REVOKED')
);

CREATE INDEX IF NOT EXISTS registered_devices_user_idx ON registered_devices (user_id, created_at);

CREATE TABLE IF NOT EXISTS registered_device_attestations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES registered_devices(id),
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key_der BYTEA,
    bundle_version TEXT,
    environment TEXT,
    counter BIGINT NOT NULL CHECK (counter >= 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('ACTIVE', 'REVOKED', 'REPLACED')),
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_key TEXT,
    UNIQUE (provider, key_id)
);

CREATE INDEX IF NOT EXISTS registered_device_attestations_device_idx
    ON registered_device_attestations (device_id, provider, lifecycle_state);
CREATE UNIQUE INDEX IF NOT EXISTS registered_device_attestations_active_device_provider_idx
    ON registered_device_attestations (device_id, provider)
    WHERE lifecycle_state = 'ACTIVE';

ALTER TABLE registered_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE registered_device_attestations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON registered_devices, registered_device_attestations FROM PUBLIC;
