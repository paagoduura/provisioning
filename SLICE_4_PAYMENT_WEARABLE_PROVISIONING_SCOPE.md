# Slice 4 — Payment Wearable Provisioning Scope

## Scope boundary

The target is a production provisioning platform that can receive an issuer-authorized payment-token result, bind it to an authenticated customer and an attested wristband, personalize the wristband secure element through an approved provisioning channel, activate the credential, and manage its complete lifecycle.

The system must not assume that an ordinary Interswitch recurring-payment token is a contactless wearable payment token. Interswitch documents tokens for saved-card and recurring-payment transactions. EMV Payment Tokenisation defines a different ecosystem in which tokens are constrained to a device, merchant, payment scenario, or other domain. The Interswitch contract must therefore confirm the exact token class and whether it is authorized for wearable contactless payments before the adapter is implemented.

## 1. Identity, consent, and authorization

The platform will provide OAuth/OIDC authentication, issuer/customer identity binding, device ownership checks, consent capture, step-up authentication hooks, role-based operator authorization, and tenant/issuer isolation. Provisioning commands will require an authenticated subject, an attested device, an unexpired session, an explicit user authorization record, and an idempotency key.

The service will enforce least privilege for customer, issuer operator, support operator, and automated integration identities. It will prevent a customer from provisioning another customer’s token, prevent an operator from accessing unauthorized tenants, and prevent a device from receiving a credential belonging to a different subject.

## 2. Interswitch integration boundary

The production adapter will support the exact Interswitch contract supplied by Interswitch, including OAuth/client authentication, request signing if required, sandbox and production endpoints, token request, token status, token activation, token suspension, token resumption, token replacement, token deletion, token expiry, token metadata, and token lifecycle events.

The adapter will include strict request and response schemas, correlation IDs, idempotency, bounded retries, timeout budgets, circuit breaking, rate-limit handling, provider error mapping, safe redaction, audit events, and versioned contract tests. PAN, CVV, PIN, full token values, and other sensitive payment data will never be written to ordinary application logs.

The implementation will support webhook verification, replay protection, event deduplication, ordering checks, dead-letter handling, reconciliation against provider state, and an operator-visible discrepancy workflow. It will not treat an Interswitch payment token as writable wristband data until the provider contract explicitly says that it is a wearable-compatible EMV payment credential or provides the required network-tokenization bridge.

## 3. Provisioning orchestration and state machine

The durable state machine will include states equivalent to `CREATED`, `AUTHENTICATED`, `CONSENTED`, `TOKEN_REQUESTED`, `TOKEN_RECEIVED`, `DEVICE_READY`, `PERSONALIZATION_PENDING`, `PERSONALIZING`, `PERSONALIZED`, `ACTIVATION_PENDING`, `ACTIVE`, `SUSPENDED`, `REPLACEMENT_PENDING`, `REVOKED`, `FAILED`, and `EXPIRED`.

Every transition will be validated, persisted transactionally, correlated to the provider and device operation, and safe to retry. The system will use an outbox or equivalent durable event pattern so provider calls and internal state changes cannot silently diverge. A crash during personalization will resume safely or enter a controlled recovery state; it will never blindly repeat a non-idempotent secure-element command.

## 4. Wristband and secure-element provisioning

The software will implement the real wristband protocol only after receiving the hardware and secure-element specifications. The implementation boundary will support NFC discovery, device attestation, device capability checks, APDU exchange, command sequencing, response-status validation, secure-session establishment, encrypted personalization data, installation confirmation, rollback or recovery, secure deletion, replacement, and post-personalization verification.

Where the wristband uses GlobalPlatform, the adapter will implement only the approved card-manager and application protocol, security-domain rules, key versions, diversification inputs, receipt handling, and lifecycle commands specified by the vendor and certification package. SCP03 provides mutual authentication, integrity/data-origin authentication, and confidentiality; the exact protocol and keys must come from the secure-element owner. SCP11 or another certificate-based channel may be required instead.

The platform will support both consumer-phone provisioning and controlled factory/personalization-bureau provisioning where the product requires them. The mobile bridge will use short-lived commands, device binding, secure transport, attestation, anti-replay counters, and confirmation receipts. No generic NFC write operation will be used for payment personalization.

## 5. Cryptography and HSM services

The current AWS KMS asymmetric verification path will remain available for attestation. Payment personalization will receive a separate cryptographic boundary. Depending on the approved design, that boundary will be a PCI PTS HSM, a certified remote Crypto Service, or an approved issuer/personalization-bureau service.

The cryptographic service will provide key generation, import or injection under dual control, key versioning, derivation, wrapping and unwrapping, secure-channel session keys, signing, verification, key rotation, revocation, destruction, usage policy, audit evidence, and separation between development, certification, and production keys. Application code will never export plaintext payment keys.

## 6. Credential and device lifecycle

The platform will expose authorized operations for activate, suspend, resume, replace, revoke, delete, lost/stolen device, device transfer where permitted, token expiry, issuer revocation, account closure, and secure-element wipe. Each operation will require authorization, create an immutable audit record, update the provider where required, update the device registry, and reconcile asynchronous results.

The device registry will retain only the minimum necessary device identity material. It will bind the device to the customer, secure-element identifier, product version, attestation history, token reference, lifecycle state, and audit history without storing unnecessary PAN or raw device secrets.

## 7. Security and compliance controls

The implementation will include secrets-manager integration, HSM-backed key custody, TLS 1.3 where supported, mTLS for private integration endpoints, certificate rotation, webhook signature verification, replay defense, nonce and timestamp validation, request-size limits, rate limiting, abuse detection, secure headers, structured redaction, vulnerability scanning, dependency pinning, SBOM generation, signed builds, and tamper-evident audit logs.

The target control set will be mapped to the applicable PCI DSS, PCI Secure Software, Secure Software Lifecycle, Key Management and Operations, Token Service Provider, Card Production and Provisioning Logical/Physical, and PTS HSM requirements. The applicable standard depends on which party performs tokenization, key custody, personalization, and payment processing; software implementation alone does not grant certification.

OAuth/OIDC flows will follow the current OAuth 2.0 Security Best Current Practice, including exact redirect handling, PKCE for public clients, secure token storage, issuer and audience validation, nonce/state protection, and avoidance of insecure implicit flows.

## 8. Operations and reliability

The production service will provide health and readiness checks that include dependency status without leaking secrets, metrics for each state transition and provider outcome, distributed correlation IDs, alerting, dashboards, traceable audit records, retry queues, dead-letter queues, reconciliation jobs, controlled replay, incident controls, and disaster-recovery procedures.

Deployment will separate sandbox, certification, and production configuration. Database migrations will be forward-compatible and reversible where safe. Secrets will be injected from a secret manager. Production deployments will require signed artifacts, migration checks, smoke tests, rollback procedures, and environment-specific approval.

## 9. Test and certification evidence

The test program will include provider contract tests, schema and negative tests, token lifecycle tests, webhook signature and replay tests, idempotency tests, timeout and retry tests, authorization tests, attestation tests, secure-element APDU tests using the real hardware or approved simulator supplied by the vendor, interrupted-provisioning recovery tests, key-rotation tests, reconciliation tests, penetration testing, dependency and supply-chain checks, load tests, disaster-recovery tests, and end-to-end certification scripts.

The final acceptance gate will prove: authenticated customer to device binding; valid provider token acquisition; secure personalization; activation confirmation; payment-token lifecycle operations; revocation propagation; audit completeness; no sensitive-data leakage; recovery from provider, network, phone, and wristband failures; and successful certification evidence from the issuer, Interswitch, network, secure-element provider, and relevant PCI/EMV programs.

## Required external inputs before implementation of the real adapters

The following must be supplied by the integration parties: Interswitch API and tokenization contract; token type and lifecycle documentation; sandbox credentials; webhook signing rules; issuer authorization model; Visa, Mastercard, Verve, or other scheme requirements; wristband model; secure-element vendor and datasheet; APDU or vendor SDK specification; GlobalPlatform profile if applicable; personalization keys or approved key-injection process; HSM/Crypto Service contract; mobile provisioning protocol; certification test plan; and production operational contacts.

Without these inputs, the repository can implement interfaces, state management, security boundaries, contract-test harnesses, and fail-closed adapters, but it must not invent token fields, APDU commands, scheme cryptography, or provider behavior.

## Standards and source basis

The design is based on EMVCo Payment Tokenisation, GlobalPlatform Secure Channel Protocol guidance, PCI Security Standards Council standards, and the IETF OAuth 2.0 Security Best Current Practice. Digiseq publicly describes secure provisioning into secure-element wearables, token-requestor integration, and mobile or central personalization. Thales publicly describes encrypted push-provisioning orchestration across issuers, payment schemes, and OEM wallets. These capabilities demonstrate the target class of platform, but their certifications, scheme access, and proprietary protocols cannot be inferred or reproduced from public marketing material.

## Definition of done

Slice 4 is complete only when the real Interswitch contract, issuer authorization, secure-element protocol, cryptographic boundary, certification test suite, and production operational controls have all been integrated and passed against real sandbox or certification environments. Until then, the correct status is implementation-ready foundation, not certified payment-wearable provisioning.

## References

[1]: https://www.emvco.com/emv-technologies/payment-tokenisation/ "EMVCo Payment Tokenisation"
[2]: https://globalplatform.org/wp-content/uploads/2019/03/GPC_2.2_D_SCP03_v1.0.pdf "GlobalPlatform Secure Channel Protocol 03"
[3]: https://www.pcisecuritystandards.org/standards/ "PCI Security Standards Council standards overview"
[4]: https://www.rfc-editor.org/rfc/rfc9700.html "OAuth 2.0 Security Best Current Practice"
[5]: https://digiseq.co.uk/payment-ready/ "DIGISEQ Payment Ready platform"
[6]: https://docs.payments.thalescloud.io/push-provisioning "Thales Push Provisioning documentation"
[7]: https://docs.interswitchgroup.com/docs/recurring-payments "Interswitch recurring payments tokenization"
[8]: https://interswitch-docs.readme.io/docs/card-payments "Interswitch card payments tokenization"
