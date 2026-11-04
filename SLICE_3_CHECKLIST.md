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
| Explicit provider selection | Complete | `ATTESTATION_PROVIDER` is required in staging/production; unsupported providers cannot fall back to KMS or development verification |
| HSM verification boundary | Complete, fail-closed | HSM-only port and delegation tests; unavailable HSM returns `503` |
| AWS KMS-backed production verification | Complete at adapter boundary | Asymmetric `SIGN_VERIFY` KMS adapter, exact key binding, allowlisted algorithm, signed counter envelope, AWS SDK credential chain, and fail-closed configuration |
| AWS KMS production activation | Blocked by external prerequisite | Staging key and live cryptographic path are available; production still requires approved key policy, IAM `kms:Verify` scope, deployment credentials, and an approved assertion fixture |
| CloudHSM-backed production verification | Blocked by external prerequisite | Requires approved PKCS#11 client adapter, cluster networking, crypto-user secret handling, key registry, and HSM operational controls |
| Development test provider | Complete | Explicit Ed25519-only verifier, not a platform trust substitute |
| Genuine Apple/Android devices pass | Blocked by external prerequisite | Requires real provider verifiers, app identities, vendor credentials, and device fixtures |
| Apple App Attest validation | Blocked by external prerequisite | Requires Apple App ID, root/certificate validation fixtures, and iOS test app |
| Android Play Integrity validation | Blocked by external prerequisite | Requires package identity, Google Cloud service account, and Android test app |
| Tests, race detection, vet, build | Complete | All passed; live API walkthrough and Supabase schema verification passed |
