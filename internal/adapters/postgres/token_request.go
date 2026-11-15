package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/paagoduura/provisioning/internal/domain"
)

var errTokenRequestOperationMissing = errors.New("token request operation is missing")

const sessionSelectForUpdate = `SELECT id, idempotency_key, user_id, COALESCE(device_id, ''), device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at, COALESCE(failure_code, ''), COALESCE(token_reference, ''), COALESCE(wrapped_payload, ''), COALESCE(apdu_receipt, '') FROM provisioning_sessions WHERE id = $1 FOR UPDATE`

func (r *SessionRepository) ClaimTokenRequest(ctx context.Context, sessionID string, now time.Time) (domain.TokenRequestClaim, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.TokenRequestClaim{}, fmt.Errorf("begin token request claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	session, err := scanSession(tx.QueryRow(ctx, sessionSelectForUpdate, sessionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TokenRequestClaim{}, ErrNotFound
	}
	if err != nil {
		return domain.TokenRequestClaim{}, fmt.Errorf("lock token request session: %w", err)
	}

	switch session.State {
	case domain.StateSessionAuthenticated:
		if session.Expired(now) {
			return domain.TokenRequestClaim{Session: session}, domain.ErrSessionExpired
		}
		operation := domain.TokenRequestOperation{SessionID: sessionID, IdempotencyKey: domain.TokenRequestIdempotencyKey(sessionID), Status: domain.TokenRequestPending, CreatedAt: now, UpdatedAt: now}
		tag, err := tx.Exec(ctx, `INSERT INTO token_request_operations (session_id, idempotency_key, status, created_at, updated_at) VALUES ($1,$2,$3,$4,$4) ON CONFLICT (session_id) DO NOTHING`, operation.SessionID, operation.IdempotencyKey, operation.Status, now)
		if err != nil {
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("persist token request claim: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return domain.TokenRequestClaim{Session: session}, domain.ErrTokenRequestOutcomeUnknown
		}
		if err := tx.QueryRow(ctx, `UPDATE provisioning_sessions SET state = $2, version = version + 1 WHERE id = $1 AND version = $3 RETURNING version`, sessionID, domain.StateTokenRequesting, session.Version).Scan(&session.Version); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.TokenRequestClaim{Session: session}, domain.ErrConcurrentUpdate
			}
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("advance token request claim: %w", err)
		}
		session.State = domain.StateTokenRequesting
		if err := tx.Commit(ctx); err != nil {
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("commit token request claim: %w", err)
		}
		return domain.TokenRequestClaim{Session: session, Operation: operation, Claimed: true}, nil

	case domain.StateTokenRequesting:
		operation, err := loadTokenRequestOperation(ctx, tx, sessionID, true)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
		}
		if err != nil {
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("load token request operation: %w", err)
		}
		if session.Expired(now) && operation.Status == domain.TokenRequestPending {
			operation.Status = domain.TokenRequestUnknown
			operation.LastErrorCode = "SESSION_EXPIRED_DURING_PROVIDER_REQUEST"
			operation.UpdatedAt = now
			if _, err := tx.Exec(ctx, `UPDATE token_request_operations SET status=$2, last_error_code=$3, updated_at=$4 WHERE session_id=$1 AND status=$5`, sessionID, operation.Status, operation.LastErrorCode, now, domain.TokenRequestPending); err != nil {
				return domain.TokenRequestClaim{Session: session}, fmt.Errorf("mark expired token request unknown: %w", err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.TokenRequestClaim{Session: session, Operation: operation}, fmt.Errorf("commit token request lookup: %w", err)
		}
		return domain.TokenRequestClaim{Session: session, Operation: operation}, nil

	case domain.StateTokenRequested, domain.StateTokenReceived, domain.StatePayloadWrapped, domain.StateTransferStarted, domain.StateTransferred, domain.StateDeviceVerified, domain.StateCompleted:
		if session.TokenReference == "" {
			return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
		}
		operation, err := loadTokenRequestOperation(ctx, tx, sessionID, false)
		if errors.Is(err, pgx.ErrNoRows) {
			operation = domain.TokenRequestOperation{SessionID: sessionID, IdempotencyKey: domain.TokenRequestIdempotencyKey(sessionID), Status: domain.TokenRequestSucceeded, ProviderReference: session.TokenReference}
		} else if err != nil {
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("load completed token request: %w", err)
		} else if operation.Status != domain.TokenRequestSucceeded || operation.ProviderReference != session.TokenReference {
			return domain.TokenRequestClaim{Session: session, Operation: operation}, domain.ErrTokenRequestOutcomeUnknown
		}
		if err := tx.Commit(ctx); err != nil {
			return domain.TokenRequestClaim{Session: session, Operation: operation}, fmt.Errorf("commit completed token request lookup: %w", err)
		}
		return domain.TokenRequestClaim{Session: session, Operation: operation}, nil
	default:
		return domain.TokenRequestClaim{Session: session}, domain.ErrInvalidTransition
	}
}

func (r *SessionRepository) MarkTokenRequestUnknown(ctx context.Context, sessionID, errorCode string, now time.Time) (domain.TokenRequestClaim, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.TokenRequestClaim{}, fmt.Errorf("begin unknown token request update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	session, err := scanSession(tx.QueryRow(ctx, sessionSelectForUpdate, sessionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TokenRequestClaim{}, ErrNotFound
	}
	if err != nil {
		return domain.TokenRequestClaim{}, fmt.Errorf("lock token request session for outcome update: %w", err)
	}
	operation, err := loadTokenRequestOperation(ctx, tx, sessionID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
	}
	if err != nil {
		return domain.TokenRequestClaim{Session: session}, fmt.Errorf("lock token request operation for outcome update: %w", err)
	}
	if operation.Status == domain.TokenRequestPending {
		operation.Status = domain.TokenRequestUnknown
		operation.LastErrorCode = boundedTokenRequestErrorCode(errorCode)
		operation.UpdatedAt = now
		if _, err := tx.Exec(ctx, `UPDATE token_request_operations SET status=$2, last_error_code=$3, updated_at=$4 WHERE session_id=$1 AND status=$5`, sessionID, operation.Status, operation.LastErrorCode, now, domain.TokenRequestPending); err != nil {
			return domain.TokenRequestClaim{Session: session}, fmt.Errorf("persist unknown token request outcome: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.TokenRequestClaim{Session: session, Operation: operation}, fmt.Errorf("commit unknown token request outcome: %w", err)
	}
	return domain.TokenRequestClaim{Session: session, Operation: operation}, nil
}

func (r *SessionRepository) CompleteTokenRequest(ctx context.Context, sessionID, providerReference string, now time.Time) (domain.ProvisioningSession, bool, error) {
	if strings.TrimSpace(providerReference) == "" {
		return domain.ProvisioningSession{}, false, domain.ErrTokenRequestOutcomeUnknown
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("begin token request completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	session, err := scanSession(tx.QueryRow(ctx, sessionSelectForUpdate, sessionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ProvisioningSession{}, false, ErrNotFound
	}
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("lock token request completion session: %w", err)
	}
	operation, err := loadTokenRequestOperation(ctx, tx, sessionID, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return session, false, errTokenRequestOperationMissing
	}
	if err != nil {
		return session, false, fmt.Errorf("lock token request operation for completion: %w", err)
	}
	if operation.Status == domain.TokenRequestSucceeded {
		if operation.ProviderReference != providerReference || (session.TokenReference != "" && session.TokenReference != providerReference) {
			return session, false, domain.ErrTokenRequestConflict
		}
		if session.State == domain.StateTokenRequesting && session.Expired(now) {
			if err := tx.Commit(ctx); err != nil {
				return session, false, fmt.Errorf("commit expired token request result: %w", err)
			}
			return session, false, domain.ErrSessionExpired
		}
		if err := tx.Commit(ctx); err != nil {
			return session, false, fmt.Errorf("commit idempotent token request completion: %w", err)
		}
		return session, false, nil
	}
	if session.State == domain.StateTokenReceived && session.TokenReference == providerReference {
		if err := markTokenRequestSucceeded(ctx, tx, sessionID, providerReference, now); err != nil {
			return session, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return session, false, fmt.Errorf("commit webhook-resolved token request: %w", err)
		}
		return session, false, nil
	}
	if session.State != domain.StateTokenRequesting || (operation.Status != domain.TokenRequestPending && operation.Status != domain.TokenRequestUnknown) {
		return session, false, domain.ErrInvalidTransition
	}
	if err := markTokenRequestSucceeded(ctx, tx, sessionID, providerReference, now); err != nil {
		return session, false, err
	}
	if session.Expired(now) {
		if err := tx.Commit(ctx); err != nil {
			return session, false, fmt.Errorf("commit provider result for expired session: %w", err)
		}
		return session, false, domain.ErrSessionExpired
	}
	if err := tx.QueryRow(ctx, `UPDATE provisioning_sessions SET state=$2, token_reference=$3, version=version+1 WHERE id=$1 AND version=$4 RETURNING version`, sessionID, domain.StateTokenRequested, providerReference, session.Version).Scan(&session.Version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return session, false, domain.ErrConcurrentUpdate
		}
		return session, false, fmt.Errorf("persist token request provider reference: %w", err)
	}
	session.State = domain.StateTokenRequested
	session.TokenReference = providerReference
	if err := tx.Commit(ctx); err != nil {
		return session, false, fmt.Errorf("commit token request completion: %w", err)
	}
	return session, true, nil
}

func loadTokenRequestOperation(ctx context.Context, tx pgx.Tx, sessionID string, lock bool) (domain.TokenRequestOperation, error) {
	query := `SELECT session_id, idempotency_key, status, COALESCE(provider_reference, ''), COALESCE(last_error_code, ''), created_at, updated_at FROM token_request_operations WHERE session_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var operation domain.TokenRequestOperation
	err := tx.QueryRow(ctx, query, sessionID).Scan(&operation.SessionID, &operation.IdempotencyKey, &operation.Status, &operation.ProviderReference, &operation.LastErrorCode, &operation.CreatedAt, &operation.UpdatedAt)
	return operation, err
}

func markTokenRequestSucceeded(ctx context.Context, tx pgx.Tx, sessionID, providerReference string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE token_request_operations SET status=$2, provider_reference=$3, last_error_code=NULL, updated_at=$4 WHERE session_id=$1`, sessionID, domain.TokenRequestSucceeded, providerReference, now)
	if err != nil {
		return fmt.Errorf("persist token request operation success: %w", err)
	}
	return nil
}

func boundedTokenRequestErrorCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		return value[:64]
	}
	return value
}
