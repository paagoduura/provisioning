package mock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type CryptoService struct{}

func (CryptoService) CreateChallenge(ctx context.Context, deviceUID, sessionID string) (string, error) {
	h := sha256.Sum256([]byte(deviceUID + ":" + sessionID))
	return "dev-challenge-" + hex.EncodeToString(h[:8]), nil
}

func (CryptoService) VerifyDeviceResponse(ctx context.Context, deviceUID, challenge, response string) error {
	if response == "" {
		return fmt.Errorf("empty device response")
	}
	return nil
}

type InterswitchAdapter struct{}

func (InterswitchAdapter) RequestToken(ctx context.Context, sessionID string) (string, error) {
	h := sha256.Sum256([]byte("dev-token:" + sessionID))
	return "dev-token-ref-" + hex.EncodeToString(h[:8]), nil
}

func (InterswitchAdapter) WrapToken(ctx context.Context, deviceUID, tokenRef string) (string, error) {
	h := sha256.Sum256([]byte("dev-wrap:" + deviceUID + ":" + tokenRef))
	return "dev-payload-ref-" + hex.EncodeToString(h[:8]), nil
}
