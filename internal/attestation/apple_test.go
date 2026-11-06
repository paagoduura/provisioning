package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestAppleAppAttestVerifierVerifiesAssertion(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryAppleKeyStore()
	if err := store.Put(context.Background(), "apple-key", &private.PublicKey); err != nil {
		t.Fatal(err)
	}
	challenge := Challenge{Value: "server-challenge", SessionID: "session"}
	input := Submission{Provider: AppleAppAttestProvider, KeyID: "apple-key", RequestHash: "request-1"}
	clientData, err := json.Marshal(struct {
		Challenge   string `json:"challenge"`
		RequestHash string `json:"request_hash"`
	}{challenge.Value, input.RequestHash})
	if err != nil {
		t.Fatal(err)
	}
	input.ClientData = base64.RawURLEncoding.EncodeToString(clientData)
	auth := make([]byte, 37)
	appHash := sha256.Sum256([]byte("TEAM.example.app"))
	copy(auth[:32], appHash[:])
	auth[32] = 1
	auth[36] = 1
	clientHash := sha256.Sum256(clientData)
	nonceInput := append(append([]byte{}, auth...), clientHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	signature, err := ecdsa.SignASN1(rand.Reader, private, nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := cbor.Marshal(struct {
		Signature         []byte `cbor:"signature"`
		AuthenticatorData []byte `cbor:"authenticatorData"`
	}{signature, auth})
	if err != nil {
		t.Fatal(err)
	}
	input.Assertion = base64.RawURLEncoding.EncodeToString(assertion)
	verifier := AppleAppAttestVerifier{AppID: "TEAM.example.app", AppleRoot: &x509.Certificate{}, Keys: store}
	result, err := verifier.Verify(context.Background(), challenge, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Provider != AppleAppAttestProvider || result.Counter != 1 || result.TrustLevel != "apple-app-attest-verified" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestAppleAppAttestVerifierRejectsRequestBinding(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryAppleKeyStore()
	_ = store.Put(context.Background(), "apple-key", &private.PublicKey)
	verifier := AppleAppAttestVerifier{AppID: "TEAM.example.app", AppleRoot: &x509.Certificate{}, Keys: store}
	_, err = verifier.Verify(context.Background(), Challenge{Value: "challenge"}, Submission{Provider: AppleAppAttestProvider, KeyID: "apple-key", RequestHash: "request", Assertion: "bad", ClientData: "bad"})
	if err != ErrAppleInvalidAssertion {
		t.Fatalf("expected invalid assertion before request binding, got %v", err)
	}
}

func TestAppleAppAttestVerifierFailsClosedWithoutConfiguration(t *testing.T) {
	_, err := (AppleAppAttestVerifier{}).Verify(context.Background(), Challenge{}, Submission{Provider: AppleAppAttestProvider, KeyID: "key", Assertion: "assertion", RequestHash: "request"})
	if err != ErrAppleUnavailable {
		t.Fatalf("expected unavailable verifier, got %v", err)
	}
}
