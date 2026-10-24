# Slice 3 — Device and app attestation checklist

| Criterion | Status | Evidence |
|---|---|---|
| Device discovery state transition | Complete | `POST /v1/provisioning-sessions/{id}/device-discovery` |
| One-time random server challenge | Complete | 32 random bytes, five-minute expiry, challenge ID |
| Session binding | Complete | Challenge stores and checks provisioning session ID |
| Request binding | Complete | Request hash is required and compared before verification |
| Atomic replay protection | Complete | Verify-before-consume plus repository-level atomic consume |
| Attestation counter policy | Complete | Stored counter must strictly increase for a provider key |
| Durable Supabase challenge storage | Complete | `attestation_challenges` table and indexes applied |
| Durable attestation record storage | Complete | `device_attestations` table with uniqueness constraint |
| Fail-closed production behavior | Complete | Unconfigured Apple/Android provider returns `501 Not Implemented` |
| Development test provider | Complete | Explicit Ed25519-only verifier, not a platform trust substitute |
| Apple App Attest validation | Deferred | Requires Apple App ID, root/certificate validation fixtures, and iOS test app |
| Android Play Integrity validation | Deferred | Requires package identity, Google Cloud service account, and Android test app |
| Tests, race detection, vet, build | Complete | All passed; `gofmt` reports zero files needing formatting |
