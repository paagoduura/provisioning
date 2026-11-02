package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeKMS struct {
	input *kms.VerifyInput
	valid bool
	err   error
}

func (f *fakeKMS) Verify(_ context.Context, input *kms.VerifyInput, _ ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	f.input = input
	if f.err != nil {
		return nil, f.err
	}
	return &kms.VerifyOutput{SignatureValid: f.valid}, nil
}

func TestKMSVerifierVerifiesCanonicalMessageAndCounter(t *testing.T) {
	client := &fakeKMS{valid: true}
	verifier := KMSVerifier{Client: client, KeyID: "arn:aws:kms:eu-north-1:123:key/device", Algorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
	challenge := Challenge{Value: "challenge", SessionID: "session"}
	input := Submission{Provider: KMSProvider, KeyID: verifier.KeyID, RequestHash: "request"}
	signature := []byte("signature")
	envelope, err := json.Marshal(KMSAssertion{Signature: base64.RawURLEncoding.EncodeToString(signature), Counter: 7})
	if err != nil {
		t.Fatal(err)
	}
	input.Assertion = base64.RawURLEncoding.EncodeToString(envelope)

	result, err := verifier.Verify(context.Background(), challenge, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Counter != 7 || result.TrustLevel != "aws-kms-hsm-verified" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if string(client.input.Message) != string(canonicalMessageWithCounter(challenge, input, 7)) {
		t.Fatal("KMS did not receive the canonical attestation message")
	}
	if client.input.KeyId == nil || *client.input.KeyId != verifier.KeyID {
		t.Fatal("KMS key binding was not preserved")
	}
}

func TestKMSVerifierFailsClosed(t *testing.T) {
	client := &fakeKMS{valid: false}
	verifier := KMSVerifier{Client: client, KeyID: "key-1", Algorithm: types.SigningAlgorithmSpecEcdsaSha256}
	input := Submission{Provider: KMSProvider, KeyID: "different-key", Assertion: "bad", RequestHash: "r"}
	if _, err := verifier.Verify(context.Background(), Challenge{}, input); !errors.Is(err, ErrKMSKeyMismatch) {
		t.Fatalf("expected key mismatch, got %v", err)
	}

	input.KeyID = verifier.KeyID
	if _, err := verifier.Verify(context.Background(), Challenge{}, input); !errors.Is(err, ErrKMSInvalidAssertion) {
		t.Fatalf("expected invalid envelope, got %v", err)
	}
}

func TestKMSVerifierClassifiesProviderErrorsAsUnavailable(t *testing.T) {
	client := &fakeKMS{err: errors.New("credential refresh failed")}
	verifier := KMSVerifier{Client: client, KeyID: "key-1", Algorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
	input := Submission{Provider: KMSProvider, KeyID: verifier.KeyID, RequestHash: "request"}
	envelope, err := json.Marshal(KMSAssertion{Signature: base64.RawURLEncoding.EncodeToString([]byte("signature")), Counter: 1})
	if err != nil {
		t.Fatal(err)
	}
	input.Assertion = base64.RawURLEncoding.EncodeToString(envelope)
	_, verifyErr := verifier.Verify(context.Background(), Challenge{}, input)
	if !errors.Is(verifyErr, ErrKMSUnavailable) {
		t.Fatalf("expected KMS unavailable, got %v", verifyErr)
	}
	if got := FailureCode(verifyErr); got != FailureHSMUnavailable {
		t.Fatalf("expected HSM unavailable failure code, got %s", got)
	}
}

func TestKMSFailureCodesAreStable(t *testing.T) {
	checks := []struct {
		err  error
		want string
	}{
		{ErrKMSKeyMismatch, FailureKMSKeyMismatch},
		{ErrKMSInvalidAssertion, FailureKMSInvalidAssertion},
		{ErrKMSInvalidSignature, FailureKMSInvalidSignature},
	}
	for _, check := range checks {
		if got := FailureCode(check.err); got != check.want {
			t.Fatalf("FailureCode(%v) = %s, want %s", check.err, got, check.want)
		}
	}
}

func TestParseKMSAlgorithmAllowlist(t *testing.T) {
	if _, err := ParseKMSAlgorithm("RSASSA_PKCS1_V1_5_SHA_256"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKMSAlgorithm("SYMMETRIC_DEFAULT"); !errors.Is(err, ErrKMSInvalidAlgorithm) {
		t.Fatalf("expected unsupported algorithm, got %v", err)
	}
}
