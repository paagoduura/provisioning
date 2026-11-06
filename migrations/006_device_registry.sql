CREATE TABLE IF NOT EXISTS registered_devices (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    device_identity_hash TEXT NOT NULL CHECK (device_identity_hash ~ '^[0-9a-f]{64}$'),
    model TEXT NOT NULL,
    transport TEXT NOT NULL CHECK (transport IN ('nfc', 'ble')),
    state TEXT NOT NULL CHECK (state IN ('DISCOVERED', 'PENDING_ATTESTATION', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'RETIRED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    suspended_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    UNIQUE (device_identity_hash)
);

CREATE INDEX IF NOT EXISTS registered_devices_owner_idx ON registered_devices (owner_id);
CREATE INDEX IF NOT EXISTS registered_devices_state_idx ON registered_devices (state);

CREATE TABLE IF NOT EXISTS registered_device_attestations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES registered_devices(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    counter BIGINT NOT NULL CHECK (counter >= 0),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    UNIQUE (device_id, provider, key_id)
);

CREATE INDEX IF NOT EXISTS registered_device_attestations_device_idx
    ON registered_device_attestations (device_id);

REVOKE ALL ON registered_devices, registered_device_attestations FROM PUBLIC;
