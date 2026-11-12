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

When `ENVIRONMENT=staging` or `ENVIRONMENT=production`, `DATABASE_URL` is mandatory and startup fails closed rather than using memory persistence. Apply `migrations/001_init.sql` through `migrations/012_readiness_migration_ledger.sql` to the target Supabase project before starting the service. Migration 006 initializes a global provider/key counter from the greatest value already stored in `device_attestations`. Migration 007 enables RLS and revokes direct grants for `anon` and `authenticated` on the application tables. Migration 008 persists the public key extracted from a validated Apple App Attest object for subsequent assertion verification. Migration 009 stores the device registry and opaque session-to-device binding; raw device identifiers are hashed in PostgreSQL. Migration 010 stores the server-built canonical request document alongside each challenge. Migration 011 adds the monotonic session version used for optimistic state-transition locking. Migration 012 creates the schema migration ledger and records the validated deployment version.

Provisioning state changes use compare-and-swap semantics. Each session has a positive `version`; a transition updates the row only when the version read by the request is still current, then increments it atomically. Concurrent stale writers receive a conflict instead of overwriting a newer state. The in-memory adapter applies the same contract for development and tests, so behavior does not change between environments.

`/healthz` is a process-liveness check. `/readyz` is a bounded dependency check and returns `503` until required checks pass. In staging and production it verifies the PostgreSQL connection, migration ledger version 12, cached or freshly fetched Supabase JWKS keys, active attestation-provider configuration, and provider readiness. AWS KMS readiness performs a non-mutating `DescribeKey` check and requires an enabled key. Google Play readiness validates the configured service-account credentials and package configuration without sending a fabricated integrity token. Apple App Attest readiness validates the configured trust anchor, identifiers, environment, and durable key lookup. The JSON response reports only check names and statuses and does not expose credentials or provider endpoint details.

The API verifies Supabase Auth access tokens against `SUPABASE_AUTH_ISSUER` and `SUPABASE_AUTH_AUDIENCE` (defaults for this project are shown in `.env.example`). It loads the project's public JWKS at startup, refreshes keys on rotation and every five minutes, and accepts only ES256 or RS256 tokens with the expected issuer, audience, expiration, a non-empty subject, and the `authenticated` role. This follows Supabase's [JWT verification guidance](https://supabase.com/docs/guides/auth/jwts) and [signing-key guidance](https://supabase.com/docs/guides/auth/signing-keys). All `/v1` routes require `Authorization: Bearer <access-token>`; health and readiness routes remain public. The `user_id` request field is no longer accepted: the verified `sub` claim becomes the session owner. A valid Supabase user login is required to obtain an access token for API use.

The selected user sign-in is Supabase email OTP or magic link. Supabase's client method is `signInWithOtp`; it sends a magic link by default, or a code when the Email Magic Link template contains `{{ .Token }}`. The client verifies a code using `verifyOtp({ email, token, type: 'email' })`, then sends the resulting access token to this API as a bearer token. See Supabase's [passwordless email guide](https://supabase.com/docs/guides/auth/auth-email-passwordless). This repository contains the backend only; the production web/mobile sign-in screen must call Supabase Auth directly with a publishable key, never the service-role key.

For a real user-to-API acceptance check, start the API and set `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, and (if needed) `OTA_API_BASE_URL` in the environment, then run `powershell -ExecutionPolicy Bypass -File scripts/auth-email-otp-e2e.ps1`. The script requests a real email OTP, securely prompts for the code, verifies it with Supabase, creates a provisioning session using the returned user access token, and reads that session back as its owner. It does not print or persist the OTP or access token. It sends an email, creates the Supabase Auth user if the address is new, and creates a provisioning session; use an address you control and treat this as a mutating live test.

Email authentication is enabled by default in Supabase, but its built-in SMTP is intended for development: delivery is restricted to project team addresses and has a low rate limit. Before production, configure a reputable custom SMTP provider, a verified sender/domain with SPF/DKIM/DMARC, the project's Site URL and exact allowed redirect URLs, email confirmation, a short OTP expiry, and the Magic Link template appropriate to code or link sign-in. Keep SMTP credentials in Supabase's protected Auth configuration, not this repository. See Supabase's [custom SMTP production guidance](https://supabase.com/docs/guides/auth/auth-smtp). These project-level settings and a real-user test remain unverified; the code and test harness alone do not certify email delivery.

Set `AWS_KMS_KEY_ID` to enable the AWS KMS verifier. The API then accepts `provider=aws-kms` only when the submitted `key_id` exactly matches that configured key. The assertion is a base64url-encoded JSON envelope containing `signature` (base64url) and a positive `counter`; the signature covers the canonical challenge message, and the counter is persisted atomically per provider/key across provisioning sessions. The runtime loads AWS credentials through the standard AWS SDK credential chain and never receives a private key.

To enable the Google Play Integrity adapter, set `ATTESTATION_PROVIDER=google-play-integrity`, `GOOGLE_PLAY_INTEGRITY_PACKAGE_NAME` to the exact Android package name, and either `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_FILE` to a secret-mounted service-account JSON file or `GOOGLE_PLAY_INTEGRITY_CREDENTIALS_JSON` from a protected secret store. The submitted assertion is a base64url-encoded JSON envelope containing the opaque `integrity_token`. The backend sends it to Google’s decode endpoint and validates the package name, the server-issued request digest, `PLAY_RECOGNIZED` app verdict, licensing when required, configured certificate digest, and allowed device-integrity verdict. Service-account keys must not be committed or printed.

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
