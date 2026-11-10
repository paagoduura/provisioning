# Secure OTA Provisioning Backend

A security-first backend foundation for wearable secure-element provisioning. This repository starts as a modular monolith with explicit boundaries for the provisioning orchestrator, device registry, Crypto/HSM adapter, Interswitch adapter, and audit trail. It can be split into independently deployed services later without changing the domain contracts.

## Current slice

- Go 1.22 HTTP API using the standard library
- Explicit provisioning state machine
- Idempotent session creation with Supabase PostgreSQL persistence when `DATABASE_URL` is configured, plus an in-memory fallback for local development
- Supabase Auth bearer-token verification using the project's asymmetric JWKS keys; session ownership is taken from the verified token subject
- Slice 3 attestation orchestration with one-time challenges, request binding, replay protection, and counter checks
- Durable device-key revocation checks, typed failure codes, redacted audit events, and an HSM-only verification port
- AWS KMS asymmetric verification adapter; KMS keeps the verification key under AWS HSM protection and is enabled only with an exact configured key ID
- Google Play Integrity decode adapter with OAuth service-account authentication, package/request-hash binding, app-recognition, licensing, certificate-digest, and device-integrity policy checks
- Mock Crypto/HSM and Interswitch adapters; **no real payment or key operations**
- Health and readiness endpoints
- PostgreSQL schema for the production persistence boundary
- Docker Compose for PostgreSQL and Redis dependencies

## Run locally

```bash
go run ./cmd/api
```

The API listens on `:8080` by default.

Set `DATABASE_URL` to the Supabase connection string to use durable PostgreSQL sessions and audit events. If it is omitted, the service uses the development-only in-memory repository.

When `ENVIRONMENT=staging` or `ENVIRONMENT=production`, `DATABASE_URL` is mandatory and startup fails closed rather than using memory persistence. Apply `migrations/001_init.sql` through `migrations/007_server_only_rls.sql` to the target Supabase project before starting the service. Migration 006 initializes a global provider/key counter from the greatest value already stored in `device_attestations`. Migration 007 enables RLS and revokes direct grants for `anon` and `authenticated` on the application tables.

The API verifies Supabase Auth access tokens against `SUPABASE_AUTH_ISSUER` and `SUPABASE_AUTH_AUDIENCE` (defaults for this project are shown in `.env.example`). It loads the project's public JWKS at startup, refreshes keys on rotation and every five minutes, and accepts only ES256 or RS256 tokens with the expected issuer, audience, expiration, a non-empty subject, and the `authenticated` role. This follows Supabase's [JWT verification guidance](https://supabase.com/docs/guides/auth/jwts) and [signing-key guidance](https://supabase.com/docs/guides/auth/signing-keys). All `/v1` routes require `Authorization: Bearer <access-token>`; health and readiness routes remain public. The `user_id` request field is no longer accepted: the verified `sub` claim becomes the session owner. A valid Supabase user login is required to obtain an access token for API use.

Set `AWS_KMS_KEY_ID` to enable the AWS KMS verifier. The API then accepts `provider=aws-kms` only when the submitted `key_id` exactly matches that configured key. The assertion is a base64url-encoded JSON envelope containing `signature` (base64url) and a positive `counter`; the signature covers the canonical challenge message, and the counter is persisted atomically per provider/key across provisioning sessions. The runtime loads AWS credentials through the standard AWS SDK credential chain and never receives a private key.

To enable the Google Play Integrity adapter, set `ATTESTATION_PROVIDER=google-play-integrity`, `GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME` to the exact Android package name, and either `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE` to a secret-mounted service-account JSON file or `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON` from a protected secret store. The submitted assertion is a base64url-encoded JSON envelope containing the opaque `integrity_token`. The backend sends it to Google’s decode endpoint and validates the package name, request hash, `PLAY_RECOGNIZED` app verdict, licensing when required, configured certificate digest, and allowed device-integrity verdict. Service-account keys must not be committed or printed.

This repository change does not enable APIs, create service accounts, alter IAM, link Play Console, or access Google Cloud resources. Those operations remain an external deployment step. Until the Google project is linked to the Android application and valid production token fixtures are supplied, the provider must remain fail-closed in staging and production.

For a non-mutating Windows check of the external prerequisites, run `powershell -ExecutionPolicy Bypass -File scripts/google-play-integrity-preflight.ps1 -ProjectId <project-id> -PackageName <package-name> -CredentialsFile <secret-file>`. The script only reads project metadata and service-account inventory; it never enables APIs, creates accounts, changes IAM, displays key material, or changes Play Console.

This adapter is valid only for a protocol where the signing key corresponding to the configured KMS asymmetric key is the authorized verification key. AWS KMS `Verify` cannot validate arbitrary device public keys just because their IDs are submitted. It is therefore not a replacement for Apple App Attest, Android Play Integrity, or a per-device public-key registry; those providers still require their own certified verification paths.

AWS KMS must use an asymmetric `SIGN_VERIFY` key whose signing algorithm matches `AWS_KMS_SIGNING_ALGORITHM`. CloudHSM is not silently substituted: a direct CloudHSM deployment requires the separately approved PKCS#11 adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls. Until that adapter is configured, the service remains fail-closed.

For a live staging walkthrough using the configured AWS KMS key, set `SUPABASE_ACCESS_TOKEN` to a valid user access token without printing or committing it, then run `powershell -ExecutionPolicy Bypass -File scripts/staging-kms-e2e.ps1` while the API is running. The script creates a session, advances device discovery, requests a one-time challenge, signs the exact canonical message with KMS, submits the attestation, and asserts a successful `aws-kms` result. It does not print the access token, signature, or challenge.

On Windows, run `powershell -ExecutionPolicy Bypass -File scripts/set-staging-env.ps1` first. It prompts locally for the full Supabase PostgreSQL URI as a secure input, stores it as a user environment variable, and configures `ENVIRONMENT=staging`, the AWS profile, region, KMS key, and algorithm. In the same PowerShell window, set `$env:SUPABASE_ACCESS_TOKEN` to a valid user token without putting it in a script argument or source file. Start `go run ./cmd/api` from that window, then run the E2E script. The staging startup guard prevents accidental memory persistence.

```bash
curl http://localhost:8080/healthz
curl -X POST http://localhost:8080/v1/provisioning-sessions \\
  -H 'Content-Type: application/json' \\
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \\
  -H 'Idempotency-Key: demo-001' \\
  -d '{"device_uid":"demo-device-001","device_model":"wearable-v1","transport":"ble"}'
```

## Security boundary

The mobile app must never receive manufacturer master keys, HSM credentials, raw PAN, or long-lived provider credentials. The mock adapters intentionally return deterministic development values and must be replaced with certified integrations only after the device protocol, Interswitch contract, key ceremony, HSM policy, and compliance scope are approved.

Supabase application tables are server-only: RLS is enabled without client-facing policies, and direct grants are revoked from `anon` and `authenticated`. The API must connect through a trusted privileged database role. Do not expose `DATABASE_URL` to clients. Direct Supabase REST access to these tables is intentionally denied; if a future client data path is required, add verified identity-to-owner mappings and narrowly scoped RLS policies before exposing it.

Every `/v1` call must carry a valid Supabase Auth user access token. The API validates its signature using only asymmetric project public keys, pins issuer and audience, requires the `authenticated` role, and uses the signed subject for authorization. Never accept a caller-supplied `user_id` as identity. The project currently advertises ES256 public keys at the issuer's JWKS endpoint; the verifier also supports RS256 key rotation and rejects shared-secret algorithms.

## Next implementation slices

1. Configure production Supabase Auth sign-in providers and validate a real-user token-to-session end-to-end flow
2. Apple App Attest verifier with production certificate fixtures
3. Google Play Integrity production configuration and real-device fixture validation
4. Real device registry and lifecycle controls
5. HSM-backed Crypto Service over mTLS
6. Interswitch sandbox adapter with signed webhooks
7. Hardware-in-the-loop APDU contract tests
