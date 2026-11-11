ALTER TABLE attestation_challenges
    ADD COLUMN IF NOT EXISTS request_document JSONB NOT NULL DEFAULT '{}'::jsonb;

REVOKE ALL ON attestation_challenges FROM PUBLIC;
