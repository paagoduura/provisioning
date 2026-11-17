# Live staging acceptance runbook

**Status: NOT ACCEPTED — requires authorized staging access, provider contract/sandbox, and genuine device/card artifacts.**

This runbook separates non-mutating deployment preflight from integration tests that create durable provisioning state or contact payment/card providers. A successful preflight or KMS smoke test is not end-to-end staging acceptance. No provider/card tests may use mock adapters, invented provider payloads, emulated hardware, or synthetic webhook signatures as acceptance evidence.

## 1. Read-only deployment preflight

After the staging API is deployed, first run:

```powershell
$env:SUPABASE_ACCESS_TOKEN = '<short-lived user access token supplied through a secure process environment>'
powershell -ExecutionPolicy Bypass -File scripts/staging-readonly-preflight.ps1 `
  -ApiBaseUrl 'https://<authorized-staging-host>' `
  -ExpectedApiOrigin 'https://<authorized-staging-host>'
```

The script requires HTTPS and an exact expected-origin match (scheme, host, and port), then performs only `GET /healthz`, `GET /readyz`, and authenticated `GET /v1/devices`. It discards the returned device list and suppresses response bodies. It does not create or modify sessions, devices, provider tokens, webhook events, APDUs, or cards. It verifies API health, the readiness checks actually exposed by the service, and that the supplied bearer token can make an authenticated read request.

In staging/production, readiness includes an `interswitch_adapter_configuration` check. This check confirms that the real InterSwitch client and webhook verifier were wired into the process; it does **not** contact InterSwitch, validate credentials with the provider, or prove that the configured protocol profile matches the selected product. A preflight pass is not provider or device acceptance.

## 2. What the existing KMS walkthrough proves

`scripts/staging-kms-e2e.ps1` uses a real configured AWS KMS key and the running API, but generates synthetic session/device metadata and signs a backend-defined message with the server's KMS key. It checks that KMS integration and selected attestation state/replay behaviors work. It does not use a genuine wearable-held key or genuine device attestation and is not acceptance of a wearable, card, token-provider, or APDU workflow. It creates persistent test sessions; run it only in an authorized staging environment with an approved test account and cleanup/retention plan. The script uses `AWS_PROFILE` when explicitly set, otherwise the AWS default credential chain; it has no repository-specific profile default.

## 3. Required live acceptance prerequisites

The authorized acceptance owner must provision and verify all of the following outside this repository:

- An isolated staging deployment with a uniquely identified environment, durable PostgreSQL, Redis, Supabase Auth/JWKS, approved KMS/HSM configuration, secrets management, access logging, and alerting.
- A time-bounded test user and access token, plus a rollback/contact path. Never store the token in command history, source control, or CI logs.
- The selected InterSwitch/Verve product’s authoritative versioned API and webhook contract, sandbox URLs, credentials, webhook configuration, approved retries/idempotency behavior, and vendor support contact. Follow [`interswitch-acceptance.md`](interswitch-acceptance.md); the repository currently has no live provider-acceptance evidence.
- Genuine test wearable/device hardware, firmware and app versions, a provider-approved device-attestation setup, and an explicit artifact owner. Device protocol and key enrollment must be approved; do not represent the backend KMS smoke test as device-held proof.
- Provider-authorized sandbox card/token artifacts, approved test PAN/card controls where applicable, test-case authorization, provider-side revocation/cleanup, and a verified prohibition on production credentials/artifacts.
- The real card/device protocol, secure-channel requirements, APDU test vectors or provider-approved card, cryptographic key provisioning/rotation plan, and a dedicated authorized tester able to observe device/card responses.
- An approved record of the test window, run IDs, state/data cleanup plan, incident contact, and stop conditions. Retention/deletion must follow the organization's approved policy; this repository does not set legal retention periods.

Do not paste credentials, card data, raw tokens, signing keys, full provider references, or unredacted webhook bodies into issues, logs, reports, or CI artifacts. Use only approved test artifacts and security-controlled evidence storage.

## 4. Live test sequence and acceptance evidence

1. Freeze and identify the staging release commit, image digest, configuration revision, migration ledger/checksums, and test window. Verify rollback and emergency stop contacts.
2. Run the read-only preflight. Capture only the deployment identity, UTC result time, readiness-check names/statuses, and test-run ID. Stop on any failed required check.
3. Validate real user authentication and ownership using an authorized test user. Keep OTP/access tokens private. Confirm an unauthorized user cannot read or mutate another user's session/device.
4. Using the approved genuine device and protocol, execute device discovery, challenge binding, attestation, key registration/revocation behavior, and replay/expiry negative cases. Record firmware/app/device model and redacted correlation IDs; do not record secrets or raw cryptographic material.
5. Execute the product-specific InterSwitch token request and authentic provider-generated webhook cases only as specified by the vendor contract. Verify successful and negative signature cases, event ID binding, duplicate/changed-body behavior, retries, ambiguous timeout recovery, ordering, concurrency, and expiry. Do not reissue a token after an ambiguous outcome until provider state is reconciled.
6. Execute payload wrapping, secure-channel/APDU exchange, post-transfer device verification, completion, and failure/recovery tests with the genuine approved device/card path. Verify durable audit/state transitions and that sensitive payloads, card data, provider credentials, and raw responses are absent from logs/API output.
7. Verify provider-side state and local PostgreSQL state agree. Perform the authorized provider/device/card revocation and cleanup process, while preserving evidence and records required by the approved retention policy.
8. Have the engineering owner, security owner, and authorized payment/provider integration owner review results and sign the release gate. Record unresolved issues and stop/go decision through the organization's controlled change system.

Acceptance requires every applicable case to pass against real staging services, real provider sandbox behavior, and the genuine approved device/card artifacts. Any undocumented request field, signature rule, retry guarantee, device protocol assumption, or unexplained state discrepancy is a no-go. A code test, local database suite, readiness response, generated signature, mock provider, or KMS smoke alone cannot satisfy this gate.

## 5. Current limits and next input

This repository does not have access to the user's staging credentials, InterSwitch sandbox permissions, provider-side test cards, or genuine wearable/card artifacts. No live staging calls or mutations have been performed from this environment. The preflight and runbook make those dependencies explicit; completion requires the authorized operator and provider/device integration owners to supply access and approve the live test window.
