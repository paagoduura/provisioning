# InterSwitch token and webhook acceptance gate

**Status: BLOCKED — vendor contract and sandbox evidence not supplied.**

This document defines what must be verified before the InterSwitch adapter can be described as accepted for a specific product. It is not an acceptance result, certification, or substitute for the product-specific integration guide. No synthetic provider responses, fabricated signatures, or simulated card/token flows count as acceptance evidence.

## Existing implementation assumptions requiring vendor confirmation

The current adapter implements OAuth client credentials using `application/x-www-form-urlencoded` with HTTP Basic client authentication. It expects JSON OAuth fields `access_token`, `token_type`, and `expires_in`; it sends a JSON token request containing `session_id`; and it expects a JSON response containing `token_reference`.

Webhook verification currently reads `X-Interswitch-Timestamp`, `X-Interswitch-Signature`, and `X-Interswitch-Event-Id`. It computes HMAC-SHA-256 over the timestamp string, a newline, and the raw body; accepts a hex signature optionally prefixed by `sha256=`; and checks a bounded timestamp window. The event-ID header is not part of the signed bytes. These are code behaviors only—not confirmed InterSwitch requirements. Do not enable the idempotency header setting unless InterSwitch has confirmed the exact header and semantics for the selected product.

## Required contract artifacts before protocol changes

Obtain and retain the authoritative, versioned product documentation or written provider confirmation for:

1. **Product and environment identity:** exact card/token product, API version, sandbox base URLs, production URLs, supported regions, and provider support contact/escalation path.
2. **OAuth:** grant type, client-authentication method, required form fields/scopes/audience, token response schema, token type and expiry semantics, clock tolerance, credential rotation, rate limits, and OAuth error responses.
3. **Token request:** exact method/path, required headers, request and response schemas, identifier semantics, correlation fields, validation errors, synchronous versus asynchronous outcomes, and whether the provider can return a result after a client timeout.
4. **Idempotency and retry:** whether an idempotency key is supported; exact header/field name, character/length restrictions, scope, retention duration, duplicate response behavior, changed-payload behavior, and guarantees after timeout, rate limit, or server error. Record which status classes are retryable and the provider's backoff guidance. Do not infer support from generic HTTP or OAuth standards.
5. **Webhook authentication:** exact header names and capitalization behavior, signed canonical bytes (including separators, path/method, body bytes, and event ID if applicable), signature algorithm, encoding/prefix, key provisioning/rotation, timestamp format and replay window, comparison requirements, and failure response expected by the provider.
6. **Webhook event contract:** event ID uniqueness and scope, event types and terminal states, payload schema/version, delivery ordering, retry schedule/maximum duration, duplicate-delivery behavior, redelivery controls, and rules for event IDs reused with modified content.
7. **Sandbox operations:** supported mechanism to create/identify a dedicated non-production test session/card, trigger a token request and webhook, replay or resend events, inject provider timeout/failure responses, and clean up/revoke test artifacts.

A URL, credential set, example copied from a different product, or a successful OAuth exchange alone is not sufficient evidence for the other contract elements.

## Acceptance matrix

Run these tests only against the designated InterSwitch sandbox and provider-approved test identities. Use a dedicated staging deployment and disposable test session. Obtain explicit operational approval before any request that creates or changes a real provider-side token/card artifact.

| Area | Required live check | Evidence to record |
|---|---|---|
| OAuth | Real sandbox credential exchange; validate the documented token fields, expiry, auth method, and failure behavior | Product/API version, UTC time, redacted request correlation ID, result class; never log token or secret |
| Token request | Submit the provider-approved request shape and verify documented response fields and local state transition | Redacted provider correlation/reference fingerprint and session correlation ID |
| Idempotency | Repeat the exact request with the same confirmed key; then test changed content with the same key, if the provider supports that test | Provider-documented duplicate/conflict outcomes and local durable operation state |
| Ambiguous outcome | Cause or obtain a provider-supported timeout after submission and establish whether the provider accepted the request; verify no unsafe duplicate token is created | Provider logs/correlation ID and reconciled database state |
| Webhook signature | Accept an authentic provider-generated sandbox event; reject authentically malformed, altered-body, invalid-signature, stale, and future-dated requests as permitted by the provider test facility | Event IDs hashed/redacted as appropriate, HTTP outcomes, audit/state results |
| Event ID binding | Establish from the signed canonicalization whether the event ID is authenticated; test missing, duplicate, and changed-body reuse according to the product contract | Exact canonicalization/version and observed provider behavior |
| Delivery semantics | Observe retry, duplicate delivery, and ordering behavior; verify the documented provider retry response/status contract | Attempt sequence, UTC times, stable event-ID fingerprint, final state |
| Concurrency and expiry | Race duplicate callbacks/token attempts and test the session expiry boundary against PostgreSQL-backed staging | Session state/version, operation status, event dedupe rows; no secret/token values |
| Recovery | Restart the API between provider acceptance and callback; verify durable reconciliation without reissuing an unsafe token request | Database operation state and provider correlation evidence |

The application must return the provider-documented response code/body for an accepted webhook, or explicitly document any provider requirement that conflicts with the current API behavior. Event deduplication and state transitions must remain atomic in PostgreSQL. Any unverified request field, signature byte, retry rule, or idempotency guarantee is a **no-go**, not a reason to weaken verification.

## Evidence handling and release decision

Store the final vendor contract revision, approved sandbox test procedure, redacted results, observed discrepancies, remediation references, and sign-off in the organization's controlled change/evidence system. Do not commit secrets, access tokens, raw cardholder data, full token references, webhook secrets, or unredacted provider payloads to this repository or CI artifacts. Keep any retained test evidence under the applicable security and data-retention controls.

Release sign-off requires an engineering owner and the authorized payment/provider integration owner to confirm that the implemented request and webhook profiles match the selected product version; all applicable matrix cases pass; unresolved findings are closed or formally risk-accepted by an authorized party; production credentials and URLs are independently reviewed; and the rollback/revocation path is tested. This repository currently has **no live InterSwitch acceptance evidence**, and no provider acceptance or certification is claimed.

## Current code boundary

The existing unit tests use an in-process HTTP transport and demonstrate local client behavior only. They do not connect to InterSwitch and are not provider acceptance tests. The code's hard-coded request/response fields and webhook HMAC canonicalization must be compared with the authoritative product contract before changing or relying on them. Until that evidence is supplied and acceptance is executed, treat the adapter as unverified for the selected product and do not declare end-to-end token/webhook readiness.
