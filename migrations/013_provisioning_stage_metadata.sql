ALTER TABLE provisioning_sessions
    ADD COLUMN IF NOT EXISTS token_reference TEXT,
    ADD COLUMN IF NOT EXISTS wrapped_payload TEXT,
    ADD COLUMN IF NOT EXISTS apdu_receipt TEXT;

DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name = 'token_reference'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name = 'wrapped_payload'
    ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name = 'apdu_receipt'
    ) THEN
        RAISE EXCEPTION 'migration 013 stage metadata columns are missing';
    END IF;
END
$migration$;

INSERT INTO schema_migrations (version)
VALUES (13)
ON CONFLICT (version) DO NOTHING;

CREATE INDEX IF NOT EXISTS provisioning_sessions_token_reference_idx
    ON provisioning_sessions (token_reference)
    WHERE token_reference IS NOT NULL;

REVOKE ALL ON provisioning_sessions FROM PUBLIC;
