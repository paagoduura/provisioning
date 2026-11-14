# Secure OTA Provisioning Backend

A security-first backend foundation for wearable secure-element provisioning. This repository starts as a modular monolith with explicit boundaries for the provisioning orchestrator, device registry, Crypto/HSM adapter, Interswitch adapter, and audit trail. It can be split into independently deployed services later without changing the domain contracts.

## Current slice

- Go 1.22 HTTP API using the standard library
- Explicit provisioning state machine
- Idempotent session creation with Supabase PostgreSQL persistence when `DATABASE_URL` is configured, plus an in-memory fallback for local development
- Supabase Auth bearer-token verification using the project's asymmetric JWKS keys; session ownership is taken from the verified token subject
- Slice 3 attestation orchestration with one-time challenges, request binding, replay protection, and counter checks
- Durable device-key revocation checks, typed failure codes, redacted audit events, and an HSM-only verification port
- Owned device registry with hashed device identifiers, opaque device IDs, provider/key registration, key rotation, revocation, replacement, suspension, resumption, and retirement
- AWS KMS asymmetric verification adapter; KMS keeps the verification key under AWS HSM protection and is enabled only with an exact configured key ID
- Google Play Integrity decode adapter with OAuth service-account authentication, package/request-hash binding, app-recognition, licensing, certificate-digest, and device-integrity policy checks
- Development-only mock Crypto/HSM and token adapters; production token requests use the configured Interswitch OAuth adapter, while device crypto and APDU hardware remain explicit fail-closed ports
- Health and readiness endpoints
- Redis-backed distributed rate limiting and attestation abuse controls
- PostgreSQL schema for the production persistence boundary
- Remaining-stage orchestration behind explicit authentication, Interswitch, payload-wrapper, APDU-channel, and device-verification interfaces
- Docker Compose for PostgreSQL and Redis dependencies
- Prometheus-compatible metrics at `/metrics`, OpenTelemetry OTLP HTTP tracing, and structured security-event export

## Test strategy

Run fast unit tests with `go test ./...`. The PostgreSQL integration suite uses a real PostgreSQL server, applies the repository migrations in a private ephemeral schema, and verifies migration replay, concurrent idempotency, optimistic-lock races, and database constraint failure behavior. It never substitutes an in-memory repository for the database path. For local execution, point `DATABASE_URL` at a disposable database and run `make test-integration`; the suite removes only its generated schema. CI runs the same suite against PostgreSQL 16. Do not point this command at staging or production.

Provider acceptance is intentionally separate from database integration: Apple App Attest tests require genuine provider-signed artifacts, and the staging KMS script performs live signing and verification with the configured AWS KMS key. Do not generate synthetic provider tokens or use fabricated responses as evidence of provider interoperability. The repository's existing `scripts/staging-kms-e2e.ps1` is the opt-in live AWS KMS/API acceptance path and requires staging credentials and an authenticated user token.

## Run locally

```bash
go run ./cmd/api
```

The API listens on `:8080` by default.

### Local containers

Copy `.env.example` to `.env`, then run `make local-deps` to start PostgreSQL and Redis with health checks and loopback-only published ports. To start the containerized API, run `make local-app`; it waits for both dependencies and enables the embedded, transactionally applied migrations with `AUTO_MIGRATE=true`. Automatic migrations are rejected unless `ENVIRONMENT` is `development` or `local`, and are disabled by default outside this explicit Compose profile. `make local-down` stops the services; named database volumes remain unless explicitly removed with `docker compose down -v`.

The API still requires a reachable Supabase Auth issuer with a valid asymmetric JWKS document. The default issuer in `.env.example` is the configured Supabase project; override `SUPABASE_AUTH_ISSUER` for a local Supabase Auth service whose signing configuration publishes ES256 or RS256 public keys. Do not turn off token verification to make local startup succeed. No synthetic user rows, provider assertions, seeded credentials, or token generator are included; use a real account and provider-backed artifacts for authenticated acceptance checks.

Redis is not an unused dependency: it backs distributed rate limiting and abuse-control state. Development can fall back to bounded in-process limiting if Redis is not configured, while staging and production require Redis. The Compose profile starts Redis and configures the API to use it.

Set `DATABASE_URL` to the Supabase connection string to use durable PostgreSQL sessions and audit events. If it is omitted, the service uses the development-only in-memory repository. Set `REDIS_URL` to the Redis connection string for distributed rate limiting; staging and production require both durable PostgreSQL and Redis.

When `ENVIRONMENT=staging` or `ENVIRONMENT=production`, `DATABASE_URL` is mandatory and startup fails closed rather than using memory persistence. Apply `migrations/001_init.sql` through `migrations/014_interswitch_webhook_events.sql` through the approved deployment migration process before starting production; automatic migration startup is deliberately prohibited outside development. Migration 006 initializes a global provider/key counter from the greatest value already stored in `device_attestations`. Migration 007 enables RLS and revokes direct grants for `anon` and `authenticated` on the application tables. Migration 008 persists the public key extracted from a validated Apple App Attest object for subsequent assertion verification. Migration 009 stores the device registry and opaque session-to-device binding; raw device identifiers are hashed in PostgreSQL. Migration 010 stores the server-built canonical request document alongside each challenge. Migration 011 adds the monotonic session version used for optimistic state-transition locking. Migration 012 creates the schema migration ledger and records the validated deployment version. Migration 013 adds server-only provisioning stage metadata. Migration 014 persists webhook event IDs and SHA-256 fingerprints of the verified session/token-reference payload under a unique constraint.

Provisioning state changes use compare-and-swap semantics. Each session has a positive `version`; a transition updates the row only when the version read by the request is still current, then increments it atomically. Concurrent stale writers receive a conflict instead of overwriting a newer state. The in-memory adapter applies the same contract for development and tests, so behavior does not change between environments.

The API applies an atomic Redis Lua token bucket to the transport peer IP before authentication. Session creation adds a per-user policy. Challenge generation and attestation verification add both per-user and per-device policies. Failed cryptographic or request-binding attestation attempts place short-lived Redis penalty keys on the user and device, while expired, replayed, unavailable-provider, and persistence-related errors are not treated as attacker-controlled signature failures. Rate-limit keys contain SHA-256 identifiers rather than raw user, device, or IP values. Redis is required and must pass a live ping before staging or production startup; local development can use the bounded in-memory implementation when `REDIS_URL` is absent.

`/healthz` is a process-liveness check. `/readyz` is a bounded dependency check and returns `503` until required checks pass. In staging and production it verifies the PostgreSQL connection, migration ledger version 14, cached or freshly fetched Supabase JWKS keys, active attestation-provider configuration, and provider readiness. AWS KMS readiness performs a non-mutating `DescribeKey` check and requires an enabled key. Google Play readiness validates the configured service-account credentials and package configuration without sending a fabricated integrity token. Apple App Attest readiness validates the configured trust anchor, identifiers, environment, and durable key lookup. The JSON response reports only check names and statuses and does not expose credentials or provider endpoint details.

## Observability

`GET /metrics` exposes an application-owned Prometheus registry. HTTP request metrics use normalized route labels rather than raw paths, and dependency metrics cover readiness operations for PostgreSQL, Redis, Supabase JWKS, and the configured attestation provider. Attestation failure metrics use stable provider and failure-code labels so dashboards can group cryptographic, replay, binding, and provider-availability failures without recording assertions or tokens.

When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is configured, the service exports server spans over OTLP/HTTP with `OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES_ENVIRONMENT` resource attributes. Shutdown flushes the batch span processor. Leave the endpoint empty when trace export is intentionally disabled.

Audit events continue to be written to durable PostgreSQL in production and are also emitted as allowlisted structured JSON log records. The export excludes assertions, access tokens, raw device UIDs, and request bodies. `SECURITY_ALERT_WEBHOOK_URL` can be set to deliver failure events to an HTTPS alert receiver; payloads contain only opaque IDs and stable event codes, and are signed with `SECURITY_ALERT_WEBHOOK_SECRET` using `X-Alert-Signature: sha256=<hex>`.

## Remaining provisioning stages

After device attestation, the service exposes owner-scoped actions for session authentication, token request, token receipt, payload wrapping, APDU transfer, device verification, completion, and explicit failure. Every action validates the exact predecessor state, persists through the existing optimistic compare-and-swap repository, and records a redacted audit event. Provider failures move the session to `FAILED`; they do not silently advance it.

The Interswitch adapter uses OAuth 2.0 client credentials with TLS, strict JSON response validation, bounded HTTP clients, and no fabricated token values. Configure the exact product-specific sandbox URLs and credentials supplied by Interswitch with `INTERSWITCH_TOKEN_URL`, `INTERSWITCH_REQUEST_URL`, `INTERSWITCH_CLIENT_ID`, and `INTERSWITCH_CLIENT_SECRET`. Token webhooks require a configured secret, event ID, timestamp within a bounded replay window, and a constant-time HMAC comparison before the state transition is attempted. Migration 014 atomically commits the event ID and token-received transition, rejects reuse of an ID with different content, and stores only a SHA-256 fingerprint of the session/token-reference pair for retry idempotency. The event ID header is not included in the current HMAC input; correctness therefore relies on the signed body plus session state and payload deduplication, not on the header as an authenticated claim. The exact Interswitch webhook signature profile must match the API product contract; the adapter does not guess undocumented fields. Validate this implementation against the vendor's actual signature profile before production activation.

Payload wrapping is an injected cryptographic boundary. The provided AES-GCM wrapper binds ciphertext to the session and correlation ID and uses a fresh random nonce; production deployments should source its key from the approved HSM/KMS ceremony rather than application source or logs. APDU transfer is similarly injected through a secure-channel transport. A production hardware adapter must implement the GlobalPlatform SCP03 mutual-authentication, command-integrity, response-integrity, and confidentiality contract; without that adapter the stage fails closed instead of simulating a card.

Migration 013 adds server-side token reference, wrapped payload, and APDU receipt fields. These fields are never serialized in the public session response. Google Play Integrity attestation is returned and stored with `binding_scope: session`; its verdict is not accepted as proof of a persistent device-held key, and it does not register or revoke caller-provided key IDs. Use a separate platform credential/attestation mechanism when persistent device-key binding is required.

The API verifies Supabase Auth access tokens against `SUPABASE_AUTH_ISSUER` and `SUPABASE_AUTH_AUDIENCE` (defaults for this project are shown in `.env.example`). It loads the project's public JWKS at startup, refreshes keys on rotation and every five minutes, and accepts only ES256 or RS256 tokens with the expected issuer, audience, expiration, a non-empty subject, and the `authenticated` role. This follows Supabase's [JWT verification guidance](https://supabase.com/docs/guides/auth/jwts) and [signing-key guidance](https://supabase.com/docs/guides/auth/signing-keys). All `/v1` routes require `Authorization: Bearer <access-token>`; health and readiness routes remain public. The `user_id` request field is no longer accepted: the verified `sub` claim becomes the session owner. A valid Supabase user login is required to obtain an access token for API use.

The selected user sign-in is Supabase email OTP or magic link. Supabase's client method is `signInWithOtp`; it sends a magic link by default, or a code when the Email Magic Link template contains `{{ .Token }}`. The client verifies a code using `verifyOtp({ email, token, type: 'email' })`, then sends the resulting access token to this API as a bearer token. See Supabase's [passwordless email guide](https://supabase.com/docs/guides/auth/auth-email-passwordless). This repository contains the backend only; the production web/mobile sign-in screen must call Supabase Auth directly with a publishable key, never the service-role key.

For a real user-to-API acceptance check, start the API and set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and (if needed) `OTA_API_BASE_URL` in the environment, then run `powershell -ExecutionPolicy Bypass -File scripts/auth-email-otp-e2e.ps1`. The script requests a real email OTP, securely prompts for the code, verifies it with Supabase, creates a provisioning session using the returned user access token, and reads that session back as its owner. It does not print or persist the OTP or access token. It sends an email, creates the Supabase Auth user if the address is new, and creates a provisioning session; use an address you control and treat this as a mutating live test.

Email authentication is enabled by default in Supabase, but its built-in SMTP is intended for development: delivery is restricted to project team addresses and has a low rate limit. Before production, configure a reputable custom SMTP provider, a verified sender/domain with SPF/DKIM/DMARC, the project's Site URL and exact allowed redirect URLs, email confirmation, a short OTP expiry, and the Magic Link template appropriate to code or link sign-in. Keep SMTP credentials in Supabase's protected Auth configuration, not this repository. See Supabase's [custom SMTP production guidance](https://supabase.com/docs/guides/auth/auth-smtp). These project-level settings and a real-user test remain unverified; the code and test harness alone do not certify email delivery.

Set `AWS_KMS_KEY_ID` to enable the AWS KMS verifier. The API then accepts `provider=aws-kms` only when the submitted `key_id` exactly matches that configured key. The assertion is a base64url-encoded JSON envelope containing `signature` (base64url) and a positive `counter`; the signature covers the canonical challenge message, and the counter is persisted atomically per provider/key across provisioning sessions. The runtime loads AWS credentials through the standard AWS SDK credential chain and never receives a private key.

To enable the Google Play Integrity adapter, set `ATTESTATION_PROVIDER=google-play-integrity`, `GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME` to the exact Android package name, and either `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE` to a secret-mounted service-account JSON file or `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON` from a protected secret store. The submitted assertion is a base64url-encoded JSON envelope containing the opaque `integrity_token`; omit `key_id` because Play Integrity does not attest a stable device-held key. The backend sends the token to Google’s decode endpoint and validates the package name, server-issued request digest, `PLAY_RECOGNIZED` app verdict, licensing when required, configured certificate digest, allowed device-integrity verdict, and a bounded timestamp freshness window (five minutes by default). The response is explicitly session-scoped. Service-account keys must not be committed or printed.

To enable the Apple App Attest adapter, set `ATTESTATION_PROVIDER=apple-app-attest`, `APPLE_TEAM_ID`, `APPLE_BUNDLE_ID`, `APPLE_APP_ATTEST_ENVIRONMENT`, and `APPLE_APP_ATTEST_ROOT_CERT_FILE` to a secret-mounted copy of Apple’s official App Attestation Root CA certificate. Initial registration accepts a base64url JSON envelope containing `attestation_object`; subsequent verification accepts `assertion` and the exact client-data bytes. The verifier validates the Apple certificate chain, App ID hash, environment, credential ID, COSE P-256 key, nonce, validation category, bundle version, assertion signature, monotonic counter, challenge, and server-computed request digest. The attestation challenge endpoint has an empty request body and returns the server-built request document plus `request_digest`; clients must include that digest in Apple client data as `request_digest`. The API rejects client-supplied `request_hash` fields and does not accept caller-supplied public keys.

This repository change does not enable APIs, create service accounts, alter IAM, link Play Console, or access Google Cloud resources. Those operations remain an external deployment step. Until the Google project is linked to the Android application and valid production token fixtures are supplied, the provider must remain fail-closed in staging and production.

For a non-mutating Windows check of the external prerequisites, run `powershell -ExecutionPolicy Bypass -File scripts/google-play-integrity-preflight.ps1 -ProjectId <project-id> -PackageName <package-name> -CredentialsFile <secret-file>`. The script only reads project metadata and service-account inventory; it never enables APIs, creates accounts, changes IAM, displays key material, or changes Play Console.

This adapter is valid only for a protocol where the signing key corresponding to the configured KMS asymmetric key is the authorized verification key. AWS KMS `Verify` cannot validate arbitrary device public keys just because their IDs are submitted. It is therefore not a replacement for Apple App Attest, Android Play Integrity, or a per-device public-key registry; those providers still require their own certified verification paths.

AWS KMS must use an asymmetric `SIGN_VERIFY` key whose signing algorithm matches `AWS_KMS_SIGNING_ALGORITHM`. CloudHSM is not silently substituted: a direct CloudHSM deployment requires the separately approved PKCS#11 adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls. Until that adapter is configured, the service remains fail-closed.

For a live staging walkthrough using the configured AWS KMS key, set `SUPABASE_ACCESS_TOKEN` to a valid user access token without printing or committing it, then run `powershell -ExecutionPolicy Bypass -File scripts/staging-kms-e2e.ps1` while the API is running. The script creates a session, advances device discovery, requests a one-time challenge, signs the exact canonical message with KMS, submits the attestation, and asserts a successful `aws-kms` result. It does not print the access token, signature, or challenge.

## Device registry

The authenticated device endpoints are `GET /v1/devices`, `POST /v1/devices`, `POST /v1/devices/{device_id}/suspend`, `POST /v1/devices/{device_id}/resume`, `POST /v1/devices/{device_id}/revoke`, `POST /v1/devices/{device_id}/retire`, and `POST /v1/devices/{device_id}/replace`. Registration and replacement accept `device_uid`, `device_model`, and `transport`; revocation and lifecycle changes require a non-empty reason. Responses expose only the server-generated opaque device ID and metadata, never the raw identifier or public key.

Creating a provisioning session ensures that the authenticated user owns the device identifier and stores the opaque device ID on the session. Attestation is rejected unless the device is usable and the submitted provider/key is either newly registered for that device or already bound to it. A successfully verified new key atomically replaces the previous active key for that provider. Revocation, suspension, replacement, and retirement are enforced before cryptographic verification and are also persisted in the key lifecycle records. This follows NIST SP 800-63B authenticator binding/lifecycle guidance, NIST SP 800-57 key registration and revocation guidance, and OWASP API1:2023 object-level authorization guidance.

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

1. Configure production Supabase email OTP/magic-link delivery and validate the real-user flow with `scripts/auth-email-otp-e2e.ps1` (implementation harness ready; external SMTP and live acceptance pending)
2. Apple App Attest genuine-device acceptance using the configured iOS app and environment
3. Google Play Integrity production configuration and real-device fixture validation
4. HSM-backed Crypto Service over mTLS
5. Interswitch sandbox adapter with signed webhooks
6. Hardware-in-the-loop APDU contract tests
