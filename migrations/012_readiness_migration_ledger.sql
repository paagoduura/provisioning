CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name = 'version'
    ) THEN
        RAISE EXCEPTION 'migration 011 is not applied: provisioning_sessions.version is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'attestation_challenges' AND column_name = 'request_document'
    ) THEN
        RAISE EXCEPTION 'migration 010 is not applied: attestation_challenges.request_document is missing';
    END IF;
    IF to_regclass('registered_devices') IS NULL THEN
        RAISE EXCEPTION 'migration 009 is not applied: registered_devices is missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'device_attestations' AND column_name = 'public_key_der'
    ) THEN
        RAISE EXCEPTION 'migration 008 is not applied: device_attestations.public_key_der is missing';
    END IF;
END
$migration$;

INSERT INTO schema_migrations (version)
VALUES (12)
ON CONFLICT (version) DO NOTHING;

REVOKE ALL ON schema_migrations FROM PUBLIC;
