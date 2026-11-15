CREATE TABLE IF NOT EXISTS token_request_operations (
    session_id TEXT PRIMARY KEY REFERENCES provisioning_sessions(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'UNKNOWN', 'SUCCEEDED')),
    provider_reference TEXT,
    last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 64),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (status = 'SUCCEEDED' AND provider_reference IS NOT NULL AND length(provider_reference) > 0)
        OR (status <> 'SUCCEEDED' AND provider_reference IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS token_request_operations_status_updated_idx
    ON token_request_operations (status, updated_at);
ALTER TABLE token_request_operations ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON token_request_operations FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON token_request_operations FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON token_request_operations FROM authenticated';
    END IF;
END
$$;
