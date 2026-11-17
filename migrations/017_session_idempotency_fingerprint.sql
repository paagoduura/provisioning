ALTER TABLE provisioning_sessions
    ADD COLUMN IF NOT EXISTS request_fingerprint BYTEA;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'provisioning_sessions'::regclass
          AND conname = 'provisioning_sessions_request_fingerprint_length'
    ) THEN
        ALTER TABLE provisioning_sessions
            ADD CONSTRAINT provisioning_sessions_request_fingerprint_length
            CHECK (request_fingerprint IS NULL OR octet_length(request_fingerprint) = 32);
    END IF;
END
$migration$;

COMMENT ON COLUMN provisioning_sessions.request_fingerprint IS
    'SHA-256 of versioned canonical session-creation request; NULL only for pre-migration legacy sessions.';
