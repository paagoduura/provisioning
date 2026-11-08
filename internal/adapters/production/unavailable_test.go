package production

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableAdaptersFailClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := (UnavailableCrypto{}).CreateChallenge(ctx, "device", "session"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected crypto adapter to fail closed, got %v", err)
	}
	if err := (UnavailableCrypto{}).VerifyDeviceResponse(ctx, "device", "challenge", "response"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected crypto verification to fail closed, got %v", err)
	}
	if _, err := (UnavailableTokenProvider{}).RequestToken(ctx, "session"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected token request to fail closed, got %v", err)
	}
	if _, err := (UnavailableTokenProvider{}).WrapToken(ctx, "device", "token"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected token wrapping to fail closed, got %v", err)
	}
}
