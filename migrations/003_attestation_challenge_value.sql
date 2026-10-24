ALTER TABLE attestation_challenges ADD COLUMN IF NOT EXISTS challenge_value TEXT;
UPDATE attestation_challenges SET challenge_value = encode(challenge_hash, 'base64') WHERE challenge_value IS NULL;
ALTER TABLE attestation_challenges ALTER COLUMN challenge_value SET NOT NULL;
