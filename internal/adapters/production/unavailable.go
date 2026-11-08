package production

import (
	"context"
	"errors"
)

// ErrNotConfigured is returned when a certified external integration has not
// been configured. Production must fail closed rather than fabricate payment
// tokens, secure-element payloads, or device responses.
var ErrNotConfigured = errors.New("certified payment provisioning integration is not configured")

type UnavailableCrypto struct{}

func (UnavailableCrypto) CreateChallenge(context.Context, string, string) (string, error) {
	return "", ErrNotConfigured
}

func (UnavailableCrypto) VerifyDeviceResponse(context.Context, string, string, string) error {
	return ErrNotConfigured
}

type UnavailableTokenProvider struct{}

func (UnavailableTokenProvider) RequestToken(context.Context, string) (string, error) {
	return "", ErrNotConfigured
}

func (UnavailableTokenProvider) WrapToken(context.Context, string, string) (string, error) {
	return "", ErrNotConfigured
}

type UnavailablePersonalizer struct{}

func (UnavailablePersonalizer) Transfer(context.Context, string, string) error {
	return ErrNotConfigured
}

func (UnavailablePersonalizer) Verify(context.Context, string, string) error {
	return ErrNotConfigured
}
