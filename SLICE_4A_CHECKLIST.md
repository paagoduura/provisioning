# Slice 4A — OAuth/OIDC Identity and Device Binding

## Implemented

- [x] OIDC issuer discovery through the configured issuer metadata endpoint.
- [x] JWKS-backed signature verification using `github.com/coreos/go-oidc/v3/oidc`.
- [x] Issuer and audience validation.
- [x] Expiration and standard OIDC token validation delegated to the verifier.
- [x] Fail-closed bearer-token handling for configured environments.
- [x] Authenticated subject extraction from the `sub` claim.
- [x] Session creation bound to the authenticated subject; caller-supplied mismatched `user_id` is rejected.
- [x] Session actions restricted to the owning subject.
- [x] Device reads restricted to the owning subject.
- [x] Production startup requires OIDC issuer and audience configuration.
- [x] Health and readiness endpoints remain available for load-balancer probes.
- [x] Existing staging/KMS behavior remains compatible when OIDC is not configured.

## Configuration

```text
OIDC_ISSUER_URL=https://issuer.example.com
OIDC_AUDIENCE=provisioning-api
OIDC_REQUIRED=true
```

The service performs live issuer discovery and JWKS retrieval at startup. No signing keys, tokens, or identity fixtures are committed to the repository.

## External acceptance still required

- Configure the real issuer and audience in the deployment secret/configuration store.
- Obtain a real access/ID token from the approved identity provider.
- Verify authenticated session creation with the token subject.
- Verify a different subject receives `403 Forbidden` for the session and device.
- Verify expired, wrong-issuer, wrong-audience, and invalid-signature tokens receive `401 Unauthorized`.
- Verify JWKS rotation by allowing the provider to publish a new signing key and validating a token signed by it.
