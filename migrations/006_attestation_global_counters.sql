-- Keep replay counters global to an attestation provider/key pair rather than
-- scoped to a provisioning session. Existing values are backfilled using the
-- greatest counter already observed for each provider/key.
CREATE TABLE IF NOT EXISTS device_attestation_counters (
    provider TEXT NOT NULL,
    key_id TEXT NOT NULL,
    counter BIGINT NOT NULL CHECK (counter >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, key_id)
);

INSERT INTO device_attestation_counters (provider, key_id, counter, updated_at)
SELECT provider, key_id, MAX(counter), now()
FROM device_attestations
GROUP BY provider, key_id
ON CONFLICT (provider, key_id) DO UPDATE
SET counter = GREATEST(device_attestation_counters.counter, EXCLUDED.counter),
    updated_at = EXCLUDED.updated_at;

-- Intentionally define no client-facing policies: this internal counter is
-- accessed by the trusted backend database role only. PostgreSQL RLS is
-- default-deny for non-owner roles until an explicit policy is added.
ALTER TABLE device_attestation_counters ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON device_attestation_counters FROM PUBLIC;
