package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/attestation"
)

type AttestationRepository struct{ pool *pgxpool.Pool }

func NewAttestationRepository(pool *pgxpool.Pool) *AttestationRepository {
	return &AttestationRepository{pool: pool}
}
func (r *AttestationRepository) Create(ctx context.Context, c attestation.Challenge) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO attestation_challenges (id, session_id, challenge_value, challenge_hash, request_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, c.ID, c.SessionID, c.Value, digest(c.Value), digest(c.RequestHash), c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create attestation challenge: %w", err)
	}
	return nil
}
func (r *AttestationRepository) Get(ctx context.Context, id string) (attestation.Challenge, error) {
	var c attestation.Challenge
	var challengeHash, requestHash []byte
	var usedAt *time.Time
	err := r.pool.QueryRow(ctx, `SELECT id, session_id, challenge_value, challenge_hash, request_hash, expires_at, used_at FROM attestation_challenges WHERE id = $1`, id).Scan(&c.ID, &c.SessionID, &c.Value, &challengeHash, &requestHash, &c.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return attestation.Challenge{}, attestation.ErrChallengeNotFound
	}
	if err != nil {
		return attestation.Challenge{}, fmt.Errorf("get attestation challenge: %w", err)
	}
	c.UsedAt = usedAt
	return c, nil
}
func (r *AttestationRepository) Consume(ctx context.Context, id string, now time.Time) (attestation.Challenge, error) {
	var c attestation.Challenge
	var challengeHash, requestHash []byte
	err := r.pool.QueryRow(ctx, `UPDATE attestation_challenges SET used_at = $2 WHERE id = $1 AND used_at IS NULL AND expires_at > $2 RETURNING id, session_id, challenge_value, challenge_hash, request_hash, expires_at, used_at`, id, now).Scan(&c.ID, &c.SessionID, &c.Value, &challengeHash, &requestHash, &c.ExpiresAt, &c.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var usedAt *time.Time
		err2 := r.pool.QueryRow(ctx, `SELECT used_at, expires_at FROM attestation_challenges WHERE id = $1`, id).Scan(&usedAt, &c.ExpiresAt)
		if errors.Is(err2, pgx.ErrNoRows) {
			return attestation.Challenge{}, attestation.ErrChallengeNotFound
		}
		if usedAt != nil {
			return attestation.Challenge{}, attestation.ErrChallengeUsed
		}
		return attestation.Challenge{}, attestation.ErrChallengeExpired
	}
	if err != nil {
		return attestation.Challenge{}, fmt.Errorf("consume attestation challenge: %w", err)
	}
	return c, nil
}
func (r *AttestationRepository) SaveAttestation(ctx context.Context, sessionID string, result attestation.VerifiedResult, now time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO device_attestations (session_id, provider, key_id, counter, trust_level, created_at) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (session_id, provider, key_id) DO UPDATE SET counter = EXCLUDED.counter, trust_level = EXCLUDED.trust_level, created_at = EXCLUDED.created_at`, sessionID, result.Provider, result.KeyID, result.Counter, result.TrustLevel, now)
	if err != nil {
		return fmt.Errorf("save device attestation: %w", err)
	}
	return nil
}
func (r *AttestationRepository) LatestCounter(ctx context.Context, sessionID, provider, keyID string) (uint64, bool, error) {
	var counter uint64
	err := r.pool.QueryRow(ctx, `SELECT counter FROM device_attestations WHERE session_id = $1 AND provider = $2 AND key_id = $3 LIMIT 1`, sessionID, provider, keyID).Scan(&counter)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get attestation counter: %w", err)
	}
	return counter, true, nil
}
func (r *AttestationRepository) Revoke(ctx context.Context, provider, keyID, reason string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO device_key_revocations (provider, key_id, reason_code, revoked_at) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, key_id) DO UPDATE SET reason_code = EXCLUDED.reason_code, revoked_at = EXCLUDED.revoked_at`, provider, keyID, reason, at)
	if err != nil {
		return fmt.Errorf("revoke device key: %w", err)
	}
	return nil
}
func (r *AttestationRepository) IsRevoked(ctx context.Context, provider, keyID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_key_revocations WHERE provider = $1 AND key_id = $2)`, provider, keyID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check device key revocation: %w", err)
	}
	return exists, nil
}
func digest(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
