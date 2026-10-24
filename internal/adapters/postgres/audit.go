package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/audit"
)

type AuditSink struct{ pool *pgxpool.Pool }

func NewAuditSink(pool *pgxpool.Pool) *AuditSink { return &AuditSink{pool: pool} }
func (s *AuditSink) Record(ctx context.Context, event audit.Event) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_events (session_id, event_type, result, reason_code, event_at) VALUES ($1, $2, $3, NULLIF($4, ''), $5)`, event.SessionID, event.Type, event.Result, event.Reason, event.At)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}
