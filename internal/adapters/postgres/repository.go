package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

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
	err := r.pool.QueryRow(ctx, `INSERT INTO provisioning_sessions (id, idempotency_key, user_id, device_id, device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, failure_code, token_reference, wrapped_payload, apdu_receipt) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11, $12, NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''), NULLIF($16, '')) ON CONFLICT (idempotency_key) DO NOTHING RETURNING id`, s.ID, s.IdempotencyKey, s.UserID, s.DeviceID, hashDeviceUID(s.DeviceUID), s.DeviceModel, s.Transport, s.State, version, s.Correlation, s.CreatedAt, s.ExpiresAt, s.FailureCode, s.TokenReference, s.WrappedPayload, s.APDUReceipt).Scan(&insertedID)
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
	err := r.pool.QueryRow(ctx, `SELECT id, idempotency_key, user_id, COALESCE(device_id, ''), device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, COALESCE(failure_code, ''), COALESCE(token_reference, ''), COALESCE(wrapped_payload, ''), COALESCE(apdu_receipt, '') FROM provisioning_sessions WHERE id = $1`, id).Scan(&s.ID, &s.IdempotencyKey, &s.UserID, &s.DeviceID, &deviceHash, &s.DeviceModel, &s.Transport, &s.State, &s.Version, &s.Correlation, &s.CreatedAt, &s.ExpiresAt, &s.FailureCode, &s.TokenReference, &s.WrappedPayload, &s.APDUReceipt)
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
	err := r.pool.QueryRow(ctx, `UPDATE provisioning_sessions SET device_id = NULLIF($2, ''), state = $3, version = version + 1, failure_code = NULLIF($4, ''), token_reference = NULLIF($6, ''), wrapped_payload = NULLIF($7, ''), apdu_receipt = NULLIF($8, '') WHERE id = $1 AND version = $5 RETURNING version`, s.ID, s.DeviceID, s.State, s.FailureCode, s.Version, s.TokenReference, s.WrappedPayload, s.APDUReceipt).Scan(&nextVersion)
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

// ReceiveTokenWebhook persists event identity and the state change atomically,
// so retries remain safe across concurrent API replicas and process restarts.
func (r *SessionRepository) ReceiveTokenWebhook(ctx context.Context, event domain.TokenWebhookEvent, now time.Time) (domain.ProvisioningSession, bool, error) {
	payloadHash := sha256.Sum256([]byte(event.SessionID + "\x00" + event.TokenReference))
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("begin webhook event transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var inserted string
	err = tx.QueryRow(ctx, `INSERT INTO interswitch_webhook_events (event_id, session_id, payload_hash, received_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING event_id`, event.EventID, event.SessionID, payloadHash[:], now).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		var existingSessionID string
		var existingHash []byte
		lookupErr := tx.QueryRow(ctx, `SELECT session_id, payload_hash FROM interswitch_webhook_events WHERE event_id = $1`, event.EventID).Scan(&existingSessionID, &existingHash)
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			lookupErr = tx.QueryRow(ctx, `SELECT session_id, payload_hash FROM interswitch_webhook_events WHERE session_id = $1 AND payload_hash = $2`, event.SessionID, payloadHash[:]).Scan(&existingSessionID, &existingHash)
		}
		if lookupErr != nil {
			return domain.ProvisioningSession{}, false, fmt.Errorf("read deduplicated webhook event: %w", lookupErr)
		}
		if existingSessionID != event.SessionID || !equalHash(existingHash, payloadHash[:]) {
			return domain.ProvisioningSession{}, false, domain.ErrWebhookEventConflict
		}
		session, err := scanSession(tx.QueryRow(ctx, `SELECT id, idempotency_key, user_id, COALESCE(device_id, ''), device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, COALESCE(failure_code, ''), COALESCE(token_reference, ''), COALESCE(wrapped_payload, ''), COALESCE(apdu_receipt, '') FROM provisioning_sessions WHERE id = $1`, event.SessionID))
		if err != nil {
			return domain.ProvisioningSession{}, false, fmt.Errorf("read duplicate webhook session: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.ProvisioningSession{}, false, fmt.Errorf("commit duplicate webhook transaction: %w", err)
		}
		return session, false, nil
	}
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("record webhook event: %w", err)
	}

	var session domain.ProvisioningSession
	var deviceHash []byte
	err = tx.QueryRow(ctx, `SELECT id, idempotency_key, user_id, COALESCE(device_id, ''), device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, COALESCE(failure_code, ''), COALESCE(token_reference, ''), COALESCE(wrapped_payload, ''), COALESCE(apdu_receipt, '') FROM provisioning_sessions WHERE id = $1 FOR UPDATE`, event.SessionID).Scan(&session.ID, &session.IdempotencyKey, &session.UserID, &session.DeviceID, &deviceHash, &session.DeviceModel, &session.Transport, &session.State, &session.Version, &session.Correlation, &session.CreatedAt, &session.ExpiresAt, &session.FailureCode, &session.TokenReference, &session.WrappedPayload, &session.APDUReceipt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProvisioningSession{}, false, ErrNotFound
	}
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("lock webhook session: %w", err)
	}
	if session.TokenReference != event.TokenReference {
		return domain.ProvisioningSession{}, false, domain.ErrInvalidTransition
	}
	if session.State == domain.StateTokenReceived {
		if err := tx.Commit(ctx); err != nil {
			return domain.ProvisioningSession{}, false, fmt.Errorf("commit duplicate token notification: %w", err)
		}
		return session, false, nil
	}
	if session.State != domain.StateTokenRequested {
		return domain.ProvisioningSession{}, false, domain.ErrInvalidTransition
	}
	if err := tx.QueryRow(ctx, `UPDATE provisioning_sessions SET state = $2, version = version + 1 WHERE id = $1 AND version = $3 RETURNING version`, session.ID, domain.StateTokenReceived, session.Version).Scan(&session.Version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ProvisioningSession{}, false, domain.ErrConcurrentUpdate
		}
		return domain.ProvisioningSession{}, false, fmt.Errorf("advance webhook session: %w", err)
	}
	session.State = domain.StateTokenReceived
	if err := tx.Commit(ctx); err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("commit webhook state transition: %w", err)
	}
	return session, true, nil
}

func scanSession(row pgx.Row) (domain.ProvisioningSession, error) {
	var session domain.ProvisioningSession
	var deviceHash []byte
	err := row.Scan(&session.ID, &session.IdempotencyKey, &session.UserID, &session.DeviceID, &deviceHash, &session.DeviceModel, &session.Transport, &session.State, &session.Version, &session.Correlation, &session.CreatedAt, &session.ExpiresAt, &session.FailureCode, &session.TokenReference, &session.WrappedPayload, &session.APDUReceipt)
	return session, err
}

func equalHash(actual, expected []byte) bool {
	if len(actual) != len(expected) {
		return false
	}
	var difference byte
	for i := range actual {
		difference |= actual[i] ^ expected[i]
	}
	return difference == 0
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
