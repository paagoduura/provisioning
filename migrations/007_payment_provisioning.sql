ALTER TABLE provisioning_sessions
    ADD COLUMN IF NOT EXISTS payment_token_ref TEXT,
    ADD COLUMN IF NOT EXISTS wrapped_payload_ref TEXT;

REVOKE ALL ON provisioning_sessions FROM PUBLIC;
