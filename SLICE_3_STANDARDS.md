# Slice 3 — Device and app attestation

This slice uses one-time server challenges, request binding, replay protection, and monotonic counters. These controls are aligned with Apple App Attest server validation, Android Play Integrity standard requests, RFC 9421 HTTP Message Signatures, and RFC 9530 Content-Digest.

Apple App Attest and Android Play Integrity are provider-specific trust systems. The backend therefore exposes a provider-verification port rather than treating a client-provided boolean as proof. Production mode must have a configured provider verifier; the explicit Ed25519 provider is for development and automated tests only.

The attestation challenge is random, short-lived, bound to a provisioning session, and single-use. The request hash binds the attestation to the action being authorized. The backend stores only a challenge hash, request hash, provider key reference, counter, and trust decision. It does not store raw attestation tokens.

The Apple verifier must validate the App Attest CBOR/WebAuthn-derived object, Apple certificate chain, App ID hash, credential ID, environment, nonce, and assertion counter using Apple’s current validation guide. The Android verifier must send the encrypted Play Integrity token to Google’s decode endpoint and validate the returned package, licensing, device-integrity, request hash, and replay signals. Those provider calls require application identifiers, certificates, service-account configuration, and vendor test credentials that are not present in this repository.

## References

- Apple App Attest server validation: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
- Android Play Integrity standard requests: https://developer.android.com/google/play/integrity/standard
- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
- RFC 9530 Digest Fields: https://www.rfc-editor.org/rfc/rfc9530
