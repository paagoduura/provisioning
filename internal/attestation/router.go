package attestation

import "context"

// ProviderRouter dispatches each submission to the verifier registered for its
// provider. Missing providers fail closed through the common error path.
type ProviderRouter map[string]Verifier

func (r ProviderRouter) Verify(ctx context.Context, challenge Challenge, input Submission) (VerifiedResult, error) {
	verifier, ok := r[input.Provider]
	if !ok || verifier == nil {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	return verifier.Verify(ctx, challenge, input)
}

func (r ProviderRouter) RegisterAttestation(ctx context.Context, challenge Challenge, keyID, object string) error {
	verifier, ok := r[AppleAppAttestProvider]
	if !ok {
		return ErrUnsupportedProvider
	}
	registrar, ok := verifier.(AttestationRegistrar)
	if !ok {
		return ErrUnsupportedProvider
	}
	return registrar.RegisterAttestation(ctx, challenge, keyID, object)
}
