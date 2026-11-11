ALTER TABLE provisioning_sessions
    ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;

ALTER TABLE provisioning_sessions
    DROP CONSTRAINT IF EXISTS provisioning_sessions_version_positive;

ALTER TABLE provisioning_sessions
    ADD CONSTRAINT provisioning_sessions_version_positive CHECK (version > 0);

REVOKE ALL ON provisioning_sessions FROM PUBLIC;
