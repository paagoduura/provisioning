package attestation

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/oauth2/google"
)

var ErrProviderReadiness = errors.New("attestation provider is not ready")

type Readiness interface {
	Ready(context.Context) error
}

func ProviderReady(ctx context.Context, verifier Verifier) error {
	checker, ok := verifier.(Readiness)
	if !ok {
		return ErrProviderReadiness
	}
	return checker.Ready(ctx)
}

func (UnavailableVerifier) Ready(context.Context) error { return ErrProviderReadiness }

// KMSDescribeAPI is deliberately separate from KMSAPI so signature-verification
// test boundaries and production health checks remain independently scoped.
type KMSDescribeAPI interface {
	DescribeKey(context.Context, *kms.DescribeKeyInput, ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

func (v KMSVerifier) Ready(ctx context.Context) error {
	if v.Client == nil || strings.TrimSpace(v.KeyID) == "" || v.Algorithm == "" {
		return ErrProviderReadiness
	}
	describer, ok := v.Client.(KMSDescribeAPI)
	if !ok {
		return ErrProviderReadiness
	}
	response, err := describer.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &v.KeyID})
	if err != nil || response == nil || response.KeyMetadata == nil || response.KeyMetadata.KeyState != types.KeyStateEnabled {
		return ErrProviderReadiness
	}
	return nil
}

func (v GooglePlayIntegrityVerifier) Ready(ctx context.Context) error {
	if v.Client == nil || strings.TrimSpace(v.PackageName) == "" {
		return ErrProviderReadiness
	}
	if v.TokenSource != nil {
		return nil
	}
	if len(v.CredentialsJSON) == 0 {
		return ErrProviderReadiness
	}
	credentials, err := google.JWTConfigFromJSON(v.CredentialsJSON, "https://www.googleapis.com/auth/playintegrity")
	if err != nil || credentials == nil {
		return ErrProviderReadiness
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (v AppleAppAttestVerifier) Ready(context.Context) error {
	if v.Root == nil || len(v.Root.Subjects()) == 0 || strings.TrimSpace(v.TeamID) == "" || strings.TrimSpace(v.BundleID) == "" || (v.Environment != "development" && v.Environment != "production") || v.Keys == nil {
		return ErrProviderReadiness
	}
	return nil
}
