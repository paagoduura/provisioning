# Slice 2 — Supabase persistence checklist

| Criterion | Status | Evidence |
|---|---|---|
| Supabase project identified | Complete | Project `haytetewtgbfxnolrhjz`, active in `eu-west-2` |
| Durable provisioning-session schema | Complete | `migrations/001_init.sql` applied as `provisioning_persistence` |
| Durable idempotency key | Complete | Unique `idempotency_key` column, repository lookup, and atomic conflict handling |
| Hashed device reference at rest | Complete | SHA-256 device UID hash stored as `BYTEA`; raw UID is not written by the PostgreSQL adapter |
| Durable audit events | Complete | `audit_events` table and PostgreSQL audit sink |
| Go PostgreSQL adapter | Complete | `internal/adapters/postgres` using `pgxpool` |
| Runtime provider selection | Complete | `DATABASE_URL` selects Supabase; absent URL uses labeled development-only memory fallback |
| Tests, race detection, vet, build | Complete | All passed locally after concurrency hardening |
| Live application connection test | Deferred | `DATABASE_URL`/database password is not available in the sandbox environment; schema was verified through Supabase MCP |

The final walkthrough also verified health, readiness, session creation, idempotent replay, invalid transport rejection, oversized request rejection, security headers, request IDs, and structured request logs. The verified commit is recorded on the `main` branch of `paagoduura/provisioning`.
