# Secure OTA Provisioning Backend

A security-first backend foundation for wearable secure-element provisioning. This repository starts as a modular monolith with explicit boundaries for the provisioning orchestrator, device registry, Crypto/HSM adapter, Interswitch adapter, and audit trail. It can be split into independently deployed services later without changing the domain contracts.

## Current slice

- Go 1.22 HTTP API using the standard library
- Explicit provisioning state machine
- Idempotent session creation with Supabase PostgreSQL persistence when `DATABASE_URL` is configured, plus an in-memory fallback for local development
- Slice 3 attestation orchestration with one-time challenges, request binding, replay protection, and counter checks
- Durable device-key revocation checks, typed failure codes, redacted audit events, and an HSM-only verification port
- AWS KMS asymmetric verification adapter; KMS keeps the verification key under AWS HSM protection and is enabled only with an exact configured key ID
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

Set `AWS_KMS_KEY_ID` to enable the AWS KMS verifier. The API then accepts `provider=aws-kms` only when the submitted `key_id` exactly matches that configured key. The assertion is a base64url-encoded JSON envelope containing `signature` (base64url) and a positive `counter`; the signature covers the canonical challenge message, and the counter is protected by the existing monotonic replay policy. The runtime loads AWS credentials through the standard AWS SDK credential chain and never receives a private key.

This adapter is valid only for a protocol where the signing key corresponding to the configured KMS asymmetric key is the authorized verification key. AWS KMS `Verify` cannot validate arbitrary device public keys just because their IDs are submitted. It is therefore not a replacement for Apple App Attest, Android Play Integrity, or a per-device public-key registry; those providers still require their own certified verification paths.

AWS KMS must use an asymmetric `SIGN_VERIFY` key whose signing algorithm matches `AWS_KMS_SIGNING_ALGORITHM`. CloudHSM is not silently substituted: a direct CloudHSM deployment requires the separately approved PKCS#11 adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls. Until that adapter is configured, the service remains fail-closed.

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
2. Apple App Attest verifier with production certificate fixtures
3. Android Play Integrity verifier with Google Cloud configuration
4. Real device registry and lifecycle controls
5. HSM-backed Crypto Service over mTLS
6. Interswitch sandbox adapter with signed webhooks
7. Hardware-in-the-loop APDU contract tests
