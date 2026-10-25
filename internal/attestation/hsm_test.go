package attestation

import (
	"context"
	"errors"
	"testing"
)

type fakeHSM struct{ called bool }

func (f *fakeHSM) VerifyDeviceSignature(ctx context.Context, keyID string, message, assertion []byte) (uint64, error) {
	f.called = true
	if keyID != "device-key" || string(message) != "challenge\nrequest\nsession" || string(assertion) != "opaque-device-signature" {
		return 0, errors.New("unexpected HSM input")
	}
	return 7, nil
}

func TestHSMVerifierDelegatesOpaqueSignature(t *testing.T) {
	client := &fakeHSM{}
	result, err := (HSMVerifier{Client: client}).Verify(Challenge{Value: "challenge", SessionID: "session"}, Submission{Provider: "hsm-device", KeyID: "device-key", RequestHash: "request", Assertion: "opaque-device-signature"})
	if err != nil {
		t.Fatal(err)
	}
	if !client.called || result.Counter != 7 || result.TrustLevel != "hsm-verified" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
func TestUnavailableHSMFailsClosed(t *testing.T) {
	_, err := (HSMVerifier{Client: UnavailableHSM{}}).Verify(Challenge{Value: "c", SessionID: "s"}, Submission{Provider: "hsm-device", KeyID: "k", RequestHash: "r", Assertion: "a"})
	if err != ErrHSMUnavailable {
		t.Fatalf("expected HSM unavailable, got %v", err)
	}
}
