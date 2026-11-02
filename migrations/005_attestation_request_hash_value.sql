ALTER TABLE attestation_challenges
    ADD COLUMN IF NOT EXISTS request_hash_value TEXT;

-- Existing challenge rows cannot reconstruct the original request hash from its
-- digest. They are short-lived and are retained only to keep the migration
-- safe for an already-applied schema; new challenges always store the exact
-- request-hash value needed for canonical verification.
UPDATE attestation_challenges
SET request_hash_value = encode(request_hash, 'hex')
WHERE request_hash_value IS NULL;

ALTER TABLE attestation_challenges
    ALTER COLUMN request_hash_value SET NOT NULL;
