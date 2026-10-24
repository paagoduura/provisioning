# Security baseline

This first slice establishes the application boundary; it is not a PCI production approval.

Implemented now:

- Typed configuration with bounded request-body size and graceful shutdown timeout.
- Correlation IDs generated with cryptographically secure random bytes; caller-supplied IDs are length-limited.
- JSON logs include method, path, status, duration, and correlation ID without request bodies.
- Security response headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a restrictive `Content-Security-Policy`.
- In-memory runtime audit sink for non-sensitive lifecycle events.
- Strict state transitions and ten-minute provisioning-session expiry.
- No raw payment credentials, HSM keys, or provider secrets are accepted by the current API.

Still required before production:

- OAuth/OIDC and device/app attestation.
- PostgreSQL persistence with encrypted/hashed device references.
- HSM-backed cryptographic adapter and key ceremony.
- Interswitch sandbox certification and signed webhook verification.
- External audit sink, metrics, tracing, WAF/rate limiting, secret manager, and penetration testing.
