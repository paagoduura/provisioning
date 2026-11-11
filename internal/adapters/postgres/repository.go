package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/domain"
)

var ErrNotFound = domain.ErrSessionNotFound

type SessionRepository struct{ pool *pgxpool.Pool }

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, s domain.ProvisioningSession) (domain.ProvisioningSession, bool, error) {
	var insertedID string
	version := s.Version
	if version == 0 {
		version = 1
	}
	err := r.pool.QueryRow(ctx, `INSERT INTO provisioning_sessions (id, idempotency_key, user_id, device_id, device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, failure_code) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11, $12, NULLIF($13, '')) ON CONFLICT (idempotency_key) DO NOTHING RETURNING id`, s.ID, s.IdempotencyKey, s.UserID, s.DeviceID, hashDeviceUID(s.DeviceUID), s.DeviceModel, s.Transport, s.State, version, s.Correlation, s.CreatedAt, s.ExpiresAt, s.FailureCode).Scan(&insertedID)
	if err == nil {
		s.Version = version
		return s, true, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		existing, findErr := r.FindByIdempotencyKey(ctx, s.IdempotencyKey)
		if findErr != nil {
			return domain.ProvisioningSession{}, false, fmt.Errorf("find concurrent idempotent session: %w", findErr)
		}
		return existing, false, nil
	}
	return domain.ProvisioningSession{}, false, fmt.Errorf("create session: %w", err)
}

func (r *SessionRepository) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	var s domain.ProvisioningSession
	var deviceHash []byte
	err := r.pool.QueryRow(ctx, `SELECT id, idempotency_key, user_id, COALESCE(device_id, ''), device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, COALESCE(failure_code, '') FROM provisioning_sessions WHERE id = $1`, id).Scan(&s.ID, &s.IdempotencyKey, &s.UserID, &s.DeviceID, &deviceHash, &s.DeviceModel, &s.Transport, &s.State, &s.Version, &s.Correlation, &s.CreatedAt, &s.ExpiresAt, &s.FailureCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	if err != nil {
		return domain.ProvisioningSession{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

func (r *SessionRepository) Save(ctx context.Context, s domain.ProvisioningSession) (domain.ProvisioningSession, error) {
	if s.Version <= 0 {
		return domain.ProvisioningSession{}, domain.ErrConcurrentUpdate
	}
	var nextVersion int64
	err := r.pool.QueryRow(ctx, `UPDATE provisioning_sessions SET device_id = NULLIF($2, ''), state = $3, version = version + 1, failure_code = NULLIF($4, '') WHERE id = $1 AND version = $5 RETURNING version`, s.ID, s.DeviceID, s.State, s.FailureCode, s.Version).Scan(&nextVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if checkErr := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM provisioning_sessions WHERE id = $1)`, s.ID).Scan(&exists); checkErr != nil {
			return domain.ProvisioningSession{}, fmt.Errorf("check session version conflict: %w", checkErr)
		}
		if !exists {
			return domain.ProvisioningSession{}, ErrNotFound
		}
		return domain.ProvisioningSession{}, domain.ErrConcurrentUpdate
	}
	if err != nil {
		return domain.ProvisioningSession{}, fmt.Errorf("save session: %w", err)
	}
	s.Version = nextVersion
	return s, nil
}

func (r *SessionRepository) FindByIdempotencyKey(ctx context.Context, key string) (domain.ProvisioningSession, error) {
	var id string
	err := r.pool.QueryRow(ctx, `SELECT id FROM provisioning_sessions WHERE idempotency_key = $1`, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	if err != nil {
		return domain.ProvisioningSession{}, fmt.Errorf("find idempotency key: %w", err)
	}
	return r.Get(ctx, id)
}

func (r *SessionRepository) SaveIdempotencyKey(ctx context.Context, key, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE provisioning_sessions SET idempotency_key = $1 WHERE id = $2`, key, id)
	if err != nil {
		return fmt.Errorf("save idempotency key: %w", err)
	}
	return nil
}

func hashDeviceUID(uid string) []byte { sum := sha256.Sum256([]byte(uid)); return sum[:] }
