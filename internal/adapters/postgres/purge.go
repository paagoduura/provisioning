package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/paagoduura/provisioning/internal/retention"
)

const purgeLockKey int64 = 0x50555247454a4f42

var (
	ErrPurgeAlreadyRunning = errors.New("another retention purge is already running")
	ErrPurgeGlobalHold     = errors.New("retention purge is blocked by an active global hold")
)

// PurgeCounts reports rows physically deleted by one bounded invocation.
type PurgeCounts struct {
	AuditEvents        int64 `json:"audit_events"`
	Challenges         int64 `json:"challenges"`
	WebhookEvents      int64 `json:"webhook_events"`
	Sessions           int64 `json:"sessions"`
	DeviceAttestations int64 `json:"device_attestations"`
	TokenOperations    int64 `json:"token_operations"`
}

// PurgeExpired deletes at most Limits.BatchSize rows from each eligible table
// in one transaction. It takes a non-blocking transaction advisory lock and
// uses indexed cutoffs with SKIP LOCKED. Parent sessions are deleted only after
// all linked rows have been independently purged. Audit rows are deleted only
// after their configured age, while active global and per-session legal holds
// are enforced. Global replay counters and device-key lifecycle records are
// never deleted.
func (r *SessionRepository) PurgeExpired(ctx context.Context, now time.Time, policy retention.Policy, limits retention.Limits) (PurgeCounts, error) {
	var counts PurgeCounts
	if err := policy.Validate(); err != nil {
		return counts, err
	}
	if err := limits.Validate(); err != nil {
		return counts, err
	}
	if r == nil || r.pool == nil {
		return counts, errors.New("purge database pool is nil")
	}
	now = now.UTC()
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return counts, fmt.Errorf("begin retention purge: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, purgeLockKey).Scan(&locked); err != nil {
		return counts, fmt.Errorf("acquire retention purge lock: %w", err)
	}
	if !locked {
		return counts, ErrPurgeAlreadyRunning
	}
	var globalHold bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM provisioning_retention_holds WHERE scope='GLOBAL' AND released_at IS NULL)`).Scan(&globalHold); err != nil {
		return counts, fmt.Errorf("check global retention hold: %w", err)
	}
	if globalHold {
		return counts, ErrPurgeGlobalHold
	}

	// All cutoffs use one UTC instant; every table has its own row limit, so
	// high child-row counts cannot create unbounded deletion work. Child records
	// that remain due to age or a hold block parent-session deletion.
	if counts.AuditEvents, err = deleteAgedAuditEvents(ctx, tx, now.Add(-policy.AuditEventAge), limits.BatchSize); err != nil {
		return PurgeCounts{}, fmt.Errorf("purge audit events: %w", err)
	}
	if counts.Challenges, err = deleteAgedChallenges(ctx, tx, now.Add(-policy.ExpiredChallengeAge), limits.BatchSize); err != nil {
		return PurgeCounts{}, fmt.Errorf("purge expired challenges: %w", err)
	}
	if counts.WebhookEvents, err = deleteAgedWebhooks(ctx, tx, now.Add(-policy.WebhookEventAge), limits.BatchSize); err != nil {
		return PurgeCounts{}, fmt.Errorf("purge webhook events: %w", err)
	}
	if counts.DeviceAttestations, err = deleteExpiredSessionAttestations(ctx, tx, now.Add(-policy.ExpiredSessionAge), limits.BatchSize); err != nil {
		return PurgeCounts{}, fmt.Errorf("purge expired-session attestation records: %w", err)
	}
	if counts.TokenOperations, err = deleteResolvedSessionOperations(ctx, tx, now.Add(-policy.ExpiredSessionAge), limits.BatchSize); err != nil {
		return PurgeCounts{}, fmt.Errorf("purge resolved expired-session token operations: %w", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT s.id
		FROM provisioning_sessions AS s
		WHERE s.expires_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=s.id AND h.released_at IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM attestation_challenges AS c WHERE c.session_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM interswitch_webhook_events AS w WHERE w.session_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM device_attestations AS d WHERE d.session_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM token_request_operations AS o WHERE o.session_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM audit_events AS a WHERE a.session_id = s.id)
		  AND s.state <> 'TOKEN_REQUESTING'
		ORDER BY s.expires_at, s.id
		LIMIT $2
		FOR UPDATE OF s SKIP LOCKED`, now.Add(-policy.ExpiredSessionAge), limits.BatchSize)
	if err != nil {
		return PurgeCounts{}, fmt.Errorf("select expired sessions for purge: %w", err)
	}
	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return PurgeCounts{}, fmt.Errorf("read expired session for purge: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return PurgeCounts{}, fmt.Errorf("iterate expired sessions for purge: %w", err)
	}
	rows.Close()
	if len(sessionIDs) > 0 {
		result, err := tx.Exec(ctx, `DELETE FROM provisioning_sessions WHERE id = ANY($1::text[])`, sessionIDs)
		if err != nil {
			return PurgeCounts{}, fmt.Errorf("delete expired sessions: %w", err)
		}
		counts.Sessions = result.RowsAffected()
		if counts.Sessions != int64(len(sessionIDs)) {
			return PurgeCounts{}, fmt.Errorf("deleted %d sessions after locking %d candidates", counts.Sessions, len(sessionIDs))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return PurgeCounts{}, fmt.Errorf("commit retention purge: %w", err)
	}
	return counts, nil
}

func deleteAgedAuditEvents(ctx context.Context, tx pgx.Tx, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.Exec(ctx, `WITH candidates AS (
		SELECT a.id FROM audit_events AS a
		WHERE a.created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=a.session_id AND h.released_at IS NULL)
		ORDER BY a.created_at, a.id LIMIT $2 FOR UPDATE OF a SKIP LOCKED
	)
	DELETE FROM audit_events AS target USING candidates WHERE target.id=candidates.id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func deleteAgedChallenges(ctx context.Context, tx pgx.Tx, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.Exec(ctx, `WITH candidates AS (
		SELECT c.id FROM attestation_challenges AS c
		WHERE c.expires_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=c.session_id AND h.released_at IS NULL)
		ORDER BY c.expires_at, c.id LIMIT $2 FOR UPDATE OF c SKIP LOCKED
	)
	DELETE FROM attestation_challenges AS target USING candidates WHERE target.id=candidates.id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func deleteAgedWebhooks(ctx context.Context, tx pgx.Tx, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.Exec(ctx, `WITH candidates AS (
		SELECT w.event_id FROM interswitch_webhook_events AS w
		WHERE w.received_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=w.session_id AND h.released_at IS NULL)
		ORDER BY w.received_at, w.event_id LIMIT $2 FOR UPDATE OF w SKIP LOCKED
	)
	DELETE FROM interswitch_webhook_events AS target USING candidates WHERE target.event_id=candidates.event_id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func deleteExpiredSessionAttestations(ctx context.Context, tx pgx.Tx, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.Exec(ctx, `WITH candidates AS (
		SELECT d.id
		FROM device_attestations AS d
		JOIN provisioning_sessions AS s ON s.id = d.session_id
		WHERE s.expires_at < $1 AND d.created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=s.id AND h.released_at IS NULL)
		ORDER BY d.created_at, d.id
		LIMIT $2
		FOR UPDATE OF d SKIP LOCKED
	)
	DELETE FROM device_attestations AS target USING candidates
	WHERE target.id = candidates.id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func deleteResolvedSessionOperations(ctx context.Context, tx pgx.Tx, cutoff time.Time, batchSize int) (int64, error) {
	result, err := tx.Exec(ctx, `WITH candidates AS (
		SELECT o.session_id
		FROM token_request_operations AS o
		JOIN provisioning_sessions AS s ON s.id = o.session_id
		WHERE s.expires_at < $1 AND s.state <> 'TOKEN_REQUESTING'
		  AND o.status = 'SUCCEEDED' AND o.updated_at < $1
		  AND NOT EXISTS (SELECT 1 FROM provisioning_retention_holds AS h WHERE h.scope='SESSION' AND h.subject_id=s.id AND h.released_at IS NULL)
		ORDER BY o.updated_at, o.session_id
		LIMIT $2
		FOR UPDATE OF o SKIP LOCKED
	)
	DELETE FROM token_request_operations AS target USING candidates
	WHERE target.session_id = candidates.session_id`, cutoff, batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
