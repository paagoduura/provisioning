-- Migration 012 introduced the ledger after migrations 001–011 had already
-- run, so those earlier successful migrations were not recorded. Reaching this
-- migration proves that the ordered runner has applied or verified migrations
-- 001–015 in this schema. Record that verified baseline so future startup does
-- not replay legacy DDL indefinitely.
INSERT INTO schema_migrations (version)
SELECT version
FROM generate_series(1, 15) AS version
ON CONFLICT (version) DO NOTHING;
