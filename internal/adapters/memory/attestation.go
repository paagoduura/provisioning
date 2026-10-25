package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
)

type AttestationRepository struct {
	mu         sync.Mutex
	challenges map[string]attestation.Challenge
	records    []attestation.VerifiedResult
	revoked    map[string]string
}

func NewAttestationRepository() *AttestationRepository {
	return &AttestationRepository{challenges: make(map[string]attestation.Challenge), revoked: make(map[string]string)}
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
func (r *AttestationRepository) SaveAttestation(ctx context.Context, sessionID string, result attestation.VerifiedResult, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, result)
	return nil
}
func (r *AttestationRepository) LatestCounter(ctx context.Context, sessionID, provider, keyID string) (uint64, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.records) - 1; i >= 0; i-- {
		result := r.records[i]
		if result.Provider == provider && result.KeyID == keyID {
			return result.Counter, true, nil
		}
	}
	return 0, false, nil
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

var _ = errors.New
