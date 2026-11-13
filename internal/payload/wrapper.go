package payload

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/paagoduura/provisioning/internal/domain"
)

type Wrapper struct{ key []byte }

func NewAESGCMWrapper(key []byte) (*Wrapper, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("payload wrapping key must be 128, 192, or 256 bits")
	}
	return &Wrapper{key: append([]byte(nil), key...)}, nil
}
func (w *Wrapper) WrapPayload(ctx context.Context, session domain.ProvisioningSession, tokenReference string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	if w == nil || len(w.key) == 0 {
		return "", errors.New("payload wrapper is not configured")
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	aad := []byte(session.ID + ":" + session.Correlation)
	ciphertext := aead.Seal(nil, nonce, []byte(tokenReference), aad)
	out := append([]byte("v1."), append(nonce, ciphertext...)...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}
func (w *Wrapper) UnwrapPayload(session domain.ProvisioningSession, wrapped string) (string, error) {
	if w == nil || len(w.key) == 0 {
		return "", errors.New("payload wrapper is not configured")
	}
	raw, err := base64.RawURLEncoding.DecodeString(wrapped)
	if err != nil {
		return "", err
	}
	if len(raw) < 4 || string(raw[:3]) != "v1." {
		return "", errors.New("unsupported wrapped payload version")
	}
	block, err := aes.NewCipher(w.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aead.NonceSize()
	if len(raw) <= 3+nonceSize {
		return "", errors.New("wrapped payload is truncated")
	}
	plaintext, err := aead.Open(nil, raw[3:3+nonceSize], raw[3+nonceSize:], []byte(session.ID+":"+session.Correlation))
	if err != nil {
		return "", errors.New("unwrap payload authentication failed")
	}
	return string(plaintext), nil
}
