# Slice 3 — Device and app attestation checklist

| Criterion | Status | Evidence |
|---|---|---|
| Device discovery state transition | Complete | `POST /v1/provisioning-sessions/{id}/device-discovery` |
| One-time random server challenge | Complete | 32 random bytes, five-minute expiry, challenge ID |
| Challenge delivery | Complete | API returns challenge ID, challenge value, and expiry |
| Device signature exchange | Complete at protocol boundary | Submission endpoint binds provider, key, assertion, challenge, session, and request hash |
| Session binding | Complete | Challenge stores and checks provisioning session ID |
| Request binding | Complete | Request hash is required and compared before verification |
| Atomic replay protection | Complete | Verify-before-consume plus repository-level atomic consume |
| Challenge reuse prevention | Complete | Used challenges return `ATTESTATION_CHALLENGE_REPLAY` |
| Attestation counter policy | Complete | Stored counter must strictly increase for a provider key |
| Revoked device/key rejection | Complete | Durable revocation table plus memory/SQL lookup; acceptance test passes |
| Altered signature rejection | Complete in test verifier | Invalid Ed25519 signatures fail; real vendor assertions remain provider-specific |
| Cloned/unknown key rejection | Complete in test verifier | Unknown key IDs fail closed |
| Durable Supabase challenge storage | Complete | `attestation_challenges` table and indexes applied |
| Durable attestation record storage | Complete | `device_attestations` table with uniqueness constraint |
| Failure reason mapping | Complete | Stable `failure_code` values and status mapping at API boundary |
| Verification-data log redaction | Complete | Assertions/challenges are absent from HTTP logs; audit stores reason codes only |
| Fail-closed production behavior | Complete | Unconfigured Apple/Android provider returns `501 Not Implemented` |
| HSM verification boundary | Complete, fail-closed | HSM-only port and delegation tests; unavailable HSM returns `503` |
| AWS KMS-backed production verification | Complete at adapter boundary | Asymmetric `SIGN_VERIFY` KMS adapter, exact key binding, allowlisted algorithm, signed counter envelope, AWS SDK credential chain, and fail-closed configuration |
| AWS KMS production activation | Blocked by external prerequisite | Requires an approved asymmetric KMS key, IAM `kms:Verify` permission scoped to that key, deployment credentials, and a real-device assertion fixture |
| Staging persistence fail-closed guard | Complete | `ENVIRONMENT=staging` requires `DATABASE_URL`; regression tests cover staging rejection and development-only memory fallback |
| Repeatable live KMS E2E harness | Complete as a validation artifact | `scripts/staging-kms-e2e.ps1` performs read-only migration inspection, session creation, discovery, challenge issuance, exact canonical-message KMS signing, API verification, and final `DEVICE_ATTESTED` assertion |
| CloudHSM-backed production verification | Blocked by external prerequisite | Requires approved PKCS#11 client adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls |
| Development test provider | Complete | Explicit Ed25519-only verifier, not a platform trust substitute |
| Genuine Apple/Android devices pass | Blocked by external prerequisite | Requires real provider app identities, vendor credentials, and device fixtures |
| Apple App Attest server implementation | Complete at provider boundary | CBOR attestation registration, Apple certificate/nonce/App ID/AAGUID/key-ID checks, ECDSA assertion verification, monotonic counter enforcement, registration endpoint, and durable PostgreSQL public-key store |
| Apple App Attest live activation | Blocked by external prerequisite | Requires Apple App ID, Apple App Attest root certificate file, iOS test app using `DCAppAttestService`, and sandbox or production device fixtures |
| Android Play Integrity validation | Blocked by external prerequisite | Requires package identity, Google Cloud service account, and Android test app |
| Tests, race detection, vet, build | Complete locally | Unit tests, race tests, vet, and build pass; live API walkthrough remains dependent on the active staging endpoint, Supabase availability, and AWS credentials |
