# Secure OTA Provisioning Backend

A security-first backend foundation for wearable secure-element provisioning. This repository starts as a modular monolith with explicit boundaries for the provisioning orchestrator, device registry, Crypto/HSM adapter, Interswitch adapter, and audit trail. It can be split into independently deployed services later without changing the domain contracts.

## Current slice

- Go 1.22 HTTP API using the standard library
- Explicit provisioning state machine
- Idempotent session creation with Supabase PostgreSQL persistence when `DATABASE_URL` is configured, plus an in-memory fallback for local development
- Slice 3 attestation orchestration with one-time challenges, request binding, replay protection, and counter checks
- Durable device-key revocation checks, typed failure codes, redacted audit events, and an HSM-only verification port
- AWS KMS asymmetric verification adapter; KMS keeps the verification key under AWS HSM protection and is enabled only with an exact configured key ID
- Apple App Attest attestation registration and assertion verification with durable public-key storage
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

`ENVIRONMENT=staging` fails closed during startup unless `DATABASE_URL` is set; staging never falls back to in-memory persistence.

Run the read-only migration check and live AWS KMS attestation walkthrough from Windows PowerShell after starting the API in staging mode:

```powershell
$env:ENVIRONMENT = "staging"
$env:DATABASE_URL = "<staging connection string>"
$env:AWS_KMS_KEY_ID = "<approved asymmetric KMS key ARN>"
.\scripts\staging-kms-e2e.ps1
```

The harness creates a session, performs device discovery, issues a challenge, signs the exact canonical message with `aws kms sign`, submits the API assertion, verifies the attested response, checks the final `DEVICE_ATTESTED` state, and inspects the required migration tables without changing the database. When `APPLE_APP_ID` is set, it also requires `apple_app_attest_keys`; use `-RequireAppleSchema` to enforce that table explicitly. Use `-SkipDatabaseCheck` only for an explicitly local API run; it does not bypass the application's staging startup guard.

For the release acceptance gate, use `scripts/run-staging-kms-gate.ps1` instead of starting the API manually. The gate verifies the checked-out revision, rebuilds `provisioning-api.exe`, refuses to use an already-listening port, starts a fresh API process with the current environment, waits for `/healthz` and `/readyz`, runs the E2E harness, reports the API logs on failure, and stops the process on completion. Run it from the repository root with `DATABASE_URL`, `AWS_KMS_KEY_ID`, `AWS_REGION`, and the AWS credential chain configured:

```powershell
.\scripts\run-staging-kms-gate.ps1
```

Use `-SkipDatabaseCheck` only for a local diagnostic run. A successful release-gate run must include `PASS API KMS verification`, `PASS final attested response: session is DEVICE_ATTESTED`, and `PASS: Slice 3 staging acceptance gate completed successfully.`

Set `AWS_KMS_KEY_ID` to enable the AWS KMS verifier. The API then accepts `provider=aws-kms` only when the submitted `key_id` exactly matches that configured key. The assertion is a base64url-encoded JSON envelope containing `signature` (base64url) and a positive `counter`; the signature covers the canonical challenge message, and the counter is protected by the existing monotonic replay policy. The runtime loads AWS credentials through the standard AWS SDK credential chain and never receives a private key.

This adapter is valid only for a protocol where the signing key corresponding to the configured KMS asymmetric key is the authorized verification key. AWS KMS `Verify` cannot validate arbitrary device public keys just because their IDs are submitted. It is therefore not a replacement for Apple App Attest, Android Play Integrity, or a per-device public-key registry; those providers still require their own certified verification paths.

AWS KMS must use an asymmetric `SIGN_VERIFY` key whose signing algorithm matches `AWS_KMS_SIGNING_ALGORITHM`. CloudHSM is not silently substituted: a direct CloudHSM deployment requires the separately approved PKCS#11 adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls. Until that adapter is configured, the service remains fail-closed.

## Deploy staging to ECS Fargate

The repository includes `infra/ecs-staging.yml` and `scripts/deploy-ecs-staging.ps1` for an idempotent ECS Fargate deployment in the AWS account and region selected by the AWS CLI profile. The script discovers the default VPC's first two public subnets, creates or updates an ECR repository, stores `DATABASE_URL` in Secrets Manager, builds and pushes the container, and deploys an ECS service behind an internet-facing Application Load Balancer. The ECS task role is scoped to `kms:Verify` on the configured KMS key, and the execution role is scoped to CloudWatch Logs, ECR pull, and the database secret.

Run from the repository root after authenticating the AWS CLI. Do not put the database URL in source control:

```powershell
$env:AWS_PROFILE = "chris-stev"
$env:AWS_REGION = "eu-north-1"
$env:AWS_KMS_KEY_ID = "<approved asymmetric KMS key ARN>"
$env:DATABASE_URL = "<current private Supabase pooler URL>"
.\scripts\deploy-ecs-staging.ps1
```

The staging template intentionally uses HTTP on port 80 because no domain or ACM certificate is assumed. Before exposing it beyond controlled staging, add an ACM certificate and HTTPS listener, restrict ALB ingress, and add a domain/DNS record. ECS tasks use public IPs to reach the external Supabase pooler without requiring a NAT gateway; review that networking choice before production.

## Apple App Attest

The server supports Apple App Attest through two endpoints. First, issue a normal attestation challenge and send the app's `attestationObject` to `POST /v1/provisioning-sessions/{id}/attestation-registration` with `provider=apple-app-attest`, the App Attest `key_id`, and the same `request_hash`. The server validates the CBOR object, Apple certificate chain, App ID hash, development/sandbox/production AAGUID, zero initial counter, credential ID, public-key hash, and Apple nonce extension before storing only the certified public key. Subsequent assertions go to the existing `POST /v1/provisioning-sessions/{id}/attestation` endpoint with `assertion` containing the base64url CBOR assertion object and `client_data` containing the base64url bytes of the JSON client data that the app hashed before calling `generateAssertion`. The client data must contain the exact server `challenge` and `request_hash` values.

Configure the server with `APPLE_APP_ID` set to the App ID prefix plus bundle identifier, `APPLE_APP_ATTEST_ENVIRONMENT` set to `production`, `sandbox`, or `development`, and `APPLE_APP_ATTEST_ROOT_CERT_FILE` pointing to Apple's App Attest root certificate PEM. In staging and production, `DATABASE_URL` is required so registered public keys survive restarts. The verifier fails closed when any Apple configuration or durable key store is unavailable.

Apply `migrations/005_apple_app_attest_keys.sql` to the staging database before enabling the provider:

```powershell
psql $env:DATABASE_URL -v ON_ERROR_STOP=1 -f .\migrations\005_apple_app_attest_keys.sql
```

For ECS, store the PEM as a Secrets Manager secret and pass its ARN as `APPLE_APP_ATTEST_ROOT_CERT_SECRET_ARN`; the deployment template injects it as `APPLE_APP_ATTEST_ROOT_CERT_PEM`, avoiding a certificate file in the image. The ECS deployment script also accepts `APPLE_APP_ID` and `APPLE_APP_ATTEST_ENVIRONMENT`. If Apple variables are omitted, the Apple provider remains disabled and the existing KMS path is unaffected.

The implementation follows Apple's [server validation guide](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) and [attestation object validation guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide). A real Apple App ID, Apple root certificate file, iOS client using `DCAppAttestService`, and sandbox or production device fixture are still required to activate and exercise the path end to end. Sandbox keys and receipts cannot be reused in production.

```bash
curl http://localhost:8080/healthz
curl -X POST http://localhost:8080/v1/provisioning-sessions \\
  -H 'Content-Type: application/json' \\
  -H 'Idempotency-Key: demo-001' \\
  -d '{"user_id":"user-123","device_uid":"demo-device-001","device_model":"wearable-v1","transport":"ble"}'
```

## Security boundary

The mobile app must never receive manufacturer master keys, HSM credentials, raw PAN, or long-lived provider credentials. The mock adapters intentionally return deterministic development values and must be replaced with certified integrations only after the device protocol, Interswitch contract, key ceremony, HSM policy, and compliance scope are approved.

## Next implementation slices

1. OAuth/OIDC authentication and app/device identity integration
2. Android Play Integrity verifier with Google Cloud configuration
3. Real device registry and lifecycle controls
4. HSM-backed Crypto Service over mTLS
5. Interswitch sandbox adapter with signed webhooks
6. Hardware-in-the-loop APDU contract tests
