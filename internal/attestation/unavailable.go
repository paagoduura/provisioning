package attestation

import (
	"context"
	"errors"
)

type UnavailableVerifier struct{}

func (UnavailableVerifier) Verify(context.Context, Challenge, Submission) (VerifiedResult, error) {
	return VerifiedResult{}, ErrUnsupportedProvider
}

var _ = errors.New
