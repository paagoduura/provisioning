ALTER TABLE device_attestations
    ADD COLUMN IF NOT EXISTS public_key_der BYTEA,
    ADD COLUMN IF NOT EXISTS bundle_version TEXT,
    ADD COLUMN IF NOT EXISTS environment TEXT;

-- Apple assertion verification requires the public key extracted from the
-- previously validated attestation object. It is server-side data only.
REVOKE ALL ON device_attestations FROM PUBLIC;
