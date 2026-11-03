package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const KMSProvider = "aws-kms"

var (
	ErrKMSUnavailable      = errors.New("aws kms verification provider is unavailable")
	ErrKMSKeyMismatch      = errors.New("aws kms key is not authorized for this verifier")
	ErrKMSInvalidAssertion = errors.New("invalid aws kms assertion envelope")
	ErrKMSInvalidSignature = errors.New("aws kms signature verification failed")
	ErrKMSInvalidAlgorithm = errors.New("unsupported aws kms signing algorithm")
)

func ParseKMSAlgorithm(value string) (types.SigningAlgorithmSpec, error) {
	algorithm := types.SigningAlgorithmSpec(value)
	switch algorithm {
	case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
		types.SigningAlgorithmSpecRsassaPssSha256,
		types.SigningAlgorithmSpecRsassaPssSha384,
		types.SigningAlgorithmSpecRsassaPssSha512,
		types.SigningAlgorithmSpecEcdsaSha256,
		types.SigningAlgorithmSpecEcdsaSha384,
		types.SigningAlgorithmSpecEcdsaSha512:
		return algorithm, nil
	default:
		return "", ErrKMSInvalidAlgorithm
	}
}

// KMSAPI is the small AWS SDK boundary used by the verifier. Keeping this
// interface local makes provider behavior testable without AWS credentials.
type KMSAPI interface {
	Verify(context.Context, *kms.VerifyInput, ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

// KMSVerifier verifies an assertion using an asymmetric KMS SIGN_VERIFY key.
// KMS performs the cryptographic operation inside AWS-managed HSMs; the
// private key never enters this service. The configured key is intentionally
// exact-match bound so an attacker cannot make the API invoke arbitrary KMS
// keys by submitting a different key_id.
type KMSVerifier struct {
	Client    KMSAPI
	KeyID     string
	Algorithm types.SigningAlgorithmSpec
}

// KMSAssertion is the wire envelope carried in Submission.Assertion. The
// counter is authenticated because it is included in the signed canonical
// message envelope, and is used by the service's monotonic replay policy.
type KMSAssertion struct {
	Signature string `json:"signature"`
	Counter   uint64 `json:"counter"`
}

func (v KMSVerifier) Verify(ctx context.Context, challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != KMSProvider {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if v.Client == nil || strings.TrimSpace(v.KeyID) == "" {
		return VerifiedResult{}, ErrKMSUnavailable
	}
	if input.KeyID != v.KeyID {
		return VerifiedResult{}, ErrKMSKeyMismatch
	}
	if v.Algorithm == "" {
		return VerifiedResult{}, ErrKMSInvalidAlgorithm
	}
	assertion, err := decodeKMSAssertion(input.Assertion)
	if err != nil {
		return VerifiedResult{}, err
	}
	signature, err := decodeBase64URL(assertion.Signature)
	if err != nil || len(signature) == 0 {
		return VerifiedResult{}, ErrKMSInvalidAssertion
	}
	out, err := v.Client.Verify(ctx, &kms.VerifyInput{
		KeyId:            &v.KeyID,
		Message:          canonicalMessageWithCounter(challenge, input, assertion.Counter),
		MessageType:      types.MessageTypeRaw,
		Signature:        signature,
		SigningAlgorithm: v.Algorithm,
	})
	if err != nil {
		// A KMS API, credential, or network failure is not evidence that the
		// device signature is invalid. Preserve the fail-closed provider
		// classification so callers return a 503/HSM-unavailable result.
		return VerifiedResult{}, fmt.Errorf("%w: %v", ErrKMSUnavailable, err)
	}
	if out == nil || !out.SignatureValid {
		return VerifiedResult{}, ErrKMSInvalidSignature
	}
	return VerifiedResult{Provider: KMSProvider, KeyID: input.KeyID, Counter: assertion.Counter, TrustLevel: "aws-kms-hsm-verified"}, nil
}

func canonicalMessageWithCounter(challenge Challenge, input Submission, counter uint64) []byte {
	return []byte(string(canonicalMessage(challenge, input)) + "\n" + strconv.FormatUint(counter, 10))
}

func decodeKMSAssertion(value string) (KMSAssertion, error) {
	raw, err := decodeBase64URL(value)
	if err != nil {
		return KMSAssertion{}, ErrKMSInvalidAssertion
	}
	var assertion KMSAssertion
	if err := json.Unmarshal(raw, &assertion); err != nil || assertion.Signature == "" || assertion.Counter == 0 {
		return KMSAssertion{}, ErrKMSInvalidAssertion
	}
	return assertion, nil
}

func decodeBase64URL(value string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
