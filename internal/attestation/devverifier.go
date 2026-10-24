package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// DevEd25519Verifier is only for local development and automated tests. It is
// not an Apple App Attest or Android Play Integrity verifier.
type DevEd25519Verifier struct{ Keys map[string]ed25519.PublicKey }

func (v DevEd25519Verifier) Verify(challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != "dev-ed25519" {
		return VerifiedResult{}, errors.New("development verifier cannot verify this provider")
	}
	key, ok := v.Keys[input.KeyID]
	if !ok {
		return VerifiedResult{}, fmt.Errorf("unknown development key: %s", input.KeyID)
	}
	signature, err := base64.RawURLEncoding.DecodeString(input.Assertion)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedResult{}, errors.New("invalid development assertion encoding")
	}
	message := []byte(challenge.Value + "\n" + input.RequestHash + "\n" + challenge.SessionID)
	if !ed25519.Verify(key, message, signature) {
		return VerifiedResult{}, errors.New("development assertion verification failed")
	}
	return VerifiedResult{Provider: input.Provider, KeyID: input.KeyID, Counter: 1, TrustLevel: "development"}, nil
}
