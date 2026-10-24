package attestation

import "errors"

type UnavailableVerifier struct{}

func (UnavailableVerifier) Verify(Challenge, Submission) (VerifiedResult, error) {
	return VerifiedResult{}, ErrUnsupportedProvider
}

var _ = errors.New
