package attestation

import (
	"context"
	"errors"
)

var ErrHSMUnavailable = errors.New("hsm verification provider is unavailable")

type HSMClient interface {
	VerifyDeviceSignature(context.Context, string, []byte, []byte) (uint64, error)
}

// HSMVerifier delegates device-signature verification to the HSM. It never
// verifies device signatures in application memory.
type HSMVerifier struct{ Client HSMClient }

func (v HSMVerifier) Verify(challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != "hsm-device" {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if v.Client == nil {
		return VerifiedResult{}, ErrHSMUnavailable
	}
	counter, err := v.Client.VerifyDeviceSignature(context.Background(), input.KeyID, []byte(challenge.Value+"\n"+input.RequestHash+"\n"+challenge.SessionID), []byte(input.Assertion))
	if err != nil {
		return VerifiedResult{}, err
	}
	return VerifiedResult{Provider: input.Provider, KeyID: input.KeyID, Counter: counter, TrustLevel: "hsm-verified"}, nil
}

type UnavailableHSM struct{}

func (UnavailableHSM) VerifyDeviceSignature(context.Context, string, []byte, []byte) (uint64, error) {
	return 0, ErrHSMUnavailable
}
