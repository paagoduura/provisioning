-- These application tables are accessed through the trusted backend only.
-- No client-facing RLS policies are created: RLS denies anon/authenticated
-- row access, and direct table privileges are revoked where those Supabase
-- roles exist. The backend must use the privileged database role.
DO $migration$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'provisioning_sessions',
        'audit_events',
        'attestation_challenges',
        'device_attestations',
        'device_key_revocations',
        'registered_devices',
        'registered_device_attestations'
    ] LOOP
        IF to_regclass(format('%I.%I', 'public', table_name)) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', 'public', table_name);
            EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM PUBLIC', 'public', table_name);

            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM anon', 'public', table_name);
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
                EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM authenticated', 'public', table_name);
            END IF;
        END IF;
    END LOOP;
END
$migration$;
