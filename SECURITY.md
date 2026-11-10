# Security baseline

This first slice establishes the application boundary; it is not a PCI production approval.

Implemented now:

- Typed configuration with bounded request-body size and graceful shutdown timeout.
- Correlation IDs generated with cryptographically secure random bytes; caller-supplied IDs are length-limited.
- JSON logs include method, path, status, duration, and correlation ID without request bodies.
- Security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a restrictive `Content-Security-Policy`.
- In-memory runtime audit sink for non-sensitive lifecycle events.
- Strict state transitions and ten-minute provisioning-session expiry.
- Supabase application tables are protected by server-only RLS; direct `anon` and `authenticated` grants are revoked, and no client-facing policies are defined.
- All `/v1` API routes require a valid Supabase Auth access token verified against the configured project issuer, audience, expiration, role, and asymmetric JWKS key; the signed `sub` claim is the only session owner identity.
- Session reads and actions are owner-scoped, and cross-user idempotency-key reuse cannot return another user's session.
- Email OTP/magic-link user sign-in is selected; `scripts/auth-email-otp-e2e.ps1` exercises real OTP verification, authenticated session creation, and owner read-back without printing credentials.
- No raw payment credentials, HSM keys, or provider secrets are accepted by the current API.

Still required before production:

- Production custom SMTP, sender-domain authentication, email template/redirect policy, and a successful real-user OTP-to-session end-to-end run.
- Verification that every deployed backend uses a privileged server-side database role; `DATABASE_URL` must never be exposed to clients.
- Device/app attestation with production trust roots and genuine-device validation.
- HSM-backed cryptographic adapter and key ceremony.
- Interswitch sandbox certification and signed webhook verification.
- External audit sink, metrics, tracing, WAF/rate limiting, secret manager, and penetration testing.
