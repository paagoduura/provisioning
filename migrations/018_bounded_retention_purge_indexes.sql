-- Cover age cutoff plus deterministic bounded batch ordering for retention jobs.
CREATE INDEX IF NOT EXISTS attestation_challenges_expiry_purge_idx
    ON attestation_challenges (expires_at, id);
CREATE INDEX IF NOT EXISTS interswitch_webhook_events_received_purge_idx
    ON interswitch_webhook_events (received_at, event_id);
CREATE INDEX IF NOT EXISTS audit_events_created_purge_idx
    ON audit_events (created_at, id);
CREATE INDEX IF NOT EXISTS provisioning_sessions_expiry_purge_idx
    ON provisioning_sessions (expires_at, id);
CREATE INDEX IF NOT EXISTS attestation_challenges_session_expiry_idx
    ON attestation_challenges (session_id, expires_at);
CREATE INDEX IF NOT EXISTS interswitch_webhook_events_session_received_idx
    ON interswitch_webhook_events (session_id, received_at);
CREATE INDEX IF NOT EXISTS device_attestations_session_created_idx
    ON device_attestations (session_id, created_at);

CREATE TABLE IF NOT EXISTS provisioning_retention_holds (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('GLOBAL', 'SESSION')),
    subject_id TEXT,
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_by TEXT,
    released_at TIMESTAMPTZ,
    CHECK ((scope = 'GLOBAL' AND subject_id IS NULL) OR (scope = 'SESSION' AND subject_id IS NOT NULL AND length(subject_id) > 0)),
    CHECK ((released_by IS NULL) = (released_at IS NULL))
);

CREATE INDEX IF NOT EXISTS provisioning_retention_holds_active_scope_idx
    ON provisioning_retention_holds (scope, subject_id)
    WHERE released_at IS NULL;

ALTER TABLE provisioning_retention_holds ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON provisioning_retention_holds FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON provisioning_retention_holds FROM anon';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON provisioning_retention_holds FROM authenticated';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION lock_provisioning_retention_hold_changes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(5788623362113294146);
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION lock_provisioning_retention_hold_changes() FROM PUBLIC;
CREATE TRIGGER provisioning_retention_holds_serialize_changes
    BEFORE INSERT OR UPDATE OR DELETE ON provisioning_retention_holds
    FOR EACH ROW EXECUTE FUNCTION lock_provisioning_retention_hold_changes();
