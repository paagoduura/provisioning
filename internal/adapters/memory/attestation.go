package memory

import (
	"context"
	"sync"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
)

type AttestationRepository struct {
	mu         sync.Mutex
	challenges map[string]attestation.Challenge
	records    map[string]attestation.VerifiedResult
	revoked    map[string]string
}

func NewAttestationRepository() *AttestationRepository {
	return &AttestationRepository{challenges: make(map[string]attestation.Challenge), records: make(map[string]attestation.VerifiedResult), revoked: make(map[string]string)}
}
func (r *AttestationRepository) Create(ctx context.Context, c attestation.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.challenges[c.ID] = c
	return nil
}
func (r *AttestationRepository) Get(ctx context.Context, id string) (attestation.Challenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return attestation.Challenge{}, attestation.ErrChallengeNotFound
	}
	return c, nil
}
func (r *AttestationRepository) Consume(ctx context.Context, id string, now time.Time) (attestation.Challenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[id]
	if !ok {
		return attestation.Challenge{}, attestation.ErrChallengeNotFound
	}
	if c.UsedAt != nil {
		return attestation.Challenge{}, attestation.ErrChallengeUsed
	}
	if !now.Before(c.ExpiresAt) {
		return attestation.Challenge{}, attestation.ErrChallengeExpired
	}
	used := now
	c.UsedAt = &used
	r.challenges[id] = c
	return c, nil
}
func (r *AttestationRepository) SaveAttestationIfCounterAdvances(ctx context.Context, sessionID string, result attestation.VerifiedResult, now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := result.Provider + "\x00" + result.KeyID
	if previous, ok := r.records[key]; ok && result.Counter <= previous.Counter {
		return false, nil
	}
	r.records[key] = result
	return true, nil
}

func (r *AttestationRepository) LookupAppleAppAttestKey(ctx context.Context, keyID string) (attestation.AppleAppAttestKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result, ok := r.records[attestation.AppleAppAttestProvider+"\x00"+keyID]
	if !ok || len(result.PublicKeyDER) == 0 {
		return attestation.AppleAppAttestKey{}, attestation.ErrAppleUnavailable
	}
	return attestation.AppleAppAttestKey{PublicKeyDER: append([]byte(nil), result.PublicKeyDER...), Counter: uint32(result.Counter), BundleVersion: result.BundleVersion, Environment: result.Environment}, nil
}
func (r *AttestationRepository) Revoke(provider, keyID, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[provider+"\x00"+keyID] = reason
}
func (r *AttestationRepository) IsRevoked(ctx context.Context, provider, keyID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[provider+"\x00"+keyID]
	return ok, nil
}
