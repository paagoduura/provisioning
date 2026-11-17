//go:build integration

package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/retention"
)

func TestPostgresRetentionPurgeIsBoundedAndPreservesUnresolvedAndGlobalSecurityState(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	now := time.Date(2026, time.November, 16, 9, 0, 0, 0, time.UTC)
	policy := retention.Policy{
		ExpiredChallengeAge: 24 * time.Hour,
		ExpiredSessionAge:   48 * time.Hour,
		WebhookEventAge:     24 * time.Hour,
		AuditEventAge:       72 * time.Hour,
	}

	insertSession := func(id, state string, expires time.Time) {
		t.Helper()
		_, err := pool.Exec(ctx, `INSERT INTO provisioning_sessions
			(id, idempotency_key, user_id, device_uid_hash, device_model, transport, state, version, correlation_id, created_at, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)`, id, "idem-"+id, "retention-test-user", []byte("hashed-device"), "hardware", "ble", state, uuid.NewString(), expires.Add(-time.Hour), expires)
		if err != nil {
			t.Fatalf("insert purge fixture session %s: %v", id, err)
		}
	}
	eligibleID := uuid.NewString()
	insertSession(eligibleID, "COMPLETED", now.Add(-30*24*time.Hour))
	old := now.Add(-20 * 24 * time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events (session_id,event_type,result,reason_code,event_at,created_at) VALUES ($1,'session.completed','success',NULL,$2,$2)`, eligibleID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO attestation_challenges (id,session_id,challenge_value,challenge_hash,request_hash,request_hash_value,expires_at,created_at) VALUES ($1,$2,'value',$3,$4,'digest',$5,$6)`, uuid.NewString(), eligibleID, []byte(uuid.NewString()), []byte("request-hash"), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO interswitch_webhook_events (event_id,session_id,payload_hash,received_at) VALUES ($1,$2,$3,$4)`, "event-"+uuid.NewString(), eligibleID, make([]byte, 32), old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_attestations (session_id,provider,key_id,counter,trust_level,created_at) VALUES ($1,'integration','globally-retained-key',8,'verified',$2)`, eligibleID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_attestations (session_id,provider,key_id,counter,trust_level,created_at) VALUES ($1,'integration','second-retained-key',9,'verified',$2)`, eligibleID, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_attestation_counters (provider,key_id,counter,updated_at) VALUES ('integration','globally-retained-key',8,$1)`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO token_request_operations (session_id,idempotency_key,status,provider_reference,created_at,updated_at) VALUES ($1,$2,'SUCCEEDED','resolved-provider-ref',$3,$3)`, eligibleID, "token-"+eligibleID, old); err != nil {
		t.Fatal(err)
	}

	pendingID := uuid.NewString()
	insertSession(pendingID, "TOKEN_REQUESTING", now.Add(-30*24*time.Hour))
	if _, err := pool.Exec(ctx, `INSERT INTO token_request_operations (session_id,idempotency_key,status,created_at,updated_at) VALUES ($1,$2,'PENDING',$3,$3)`, pendingID, "token-"+pendingID, old); err != nil {
		t.Fatal(err)
	}

	recentAuditID := uuid.NewString()
	insertSession(recentAuditID, "FAILED", now.Add(-30*24*time.Hour))
	recent := now.Add(-time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events (session_id,event_type,result,event_at,created_at) VALUES ($1,'session.failed','failure',$2,$2)`, recentAuditID, recent); err != nil {
		t.Fatal(err)
	}
	boundaryID := uuid.NewString()
	insertSession(boundaryID, "FAILED", now.Add(-30*24*time.Hour))
	challengeCutoff := now.Add(-policy.ExpiredChallengeAge)
	if _, err := pool.Exec(ctx, `INSERT INTO attestation_challenges (id,session_id,challenge_value,challenge_hash,request_hash,request_hash_value,expires_at,created_at) VALUES ($1,$2,'boundary',$3,$4,'digest',$5,$5)`, uuid.NewString(), boundaryID, []byte(uuid.NewString()), []byte("boundary-request"), challengeCutoff); err != nil {
		t.Fatal(err)
	}
	heldID := uuid.NewString()
	insertSession(heldID, "FAILED", now.Add(-30*24*time.Hour))
	if _, err := pool.Exec(ctx, `INSERT INTO provisioning_retention_holds (scope,subject_id,reason_code,created_by) VALUES ('SESSION',$1,'LEGAL_HOLD','integration-test-operator')`, heldID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO attestation_challenges (id,session_id,challenge_value,challenge_hash,request_hash,request_hash_value,expires_at,created_at) VALUES ($1,$2,'held',$3,$4,'digest',$5,$6)`, uuid.NewString(), heldID, []byte(uuid.NewString()), []byte("held-request"), old, old); err != nil {
		t.Fatal(err)
	}

	counts, err := postgres.NewSessionRepository(pool).PurgeExpired(ctx, now, policy, retention.Limits{BatchSize: 1})
	if err != nil {
		t.Fatalf("run bounded purge: %v", err)
	}
	if counts.AuditEvents != 1 || counts.Challenges != 1 || counts.WebhookEvents != 1 || counts.Sessions != 0 || counts.DeviceAttestations != 1 || counts.TokenOperations != 1 {
		t.Fatalf("first bounded purge counts = %+v, want one row per child-table batch and no parent while a child remains", counts)
	}
	for _, table := range []string{"provisioning_sessions", "audit_events", "attestation_challenges", "interswitch_webhook_events", "device_attestations", "token_request_operations"} {
		var remaining int
		query := "SELECT count(*) FROM " + table
		if err := pool.QueryRow(ctx, query).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		switch table {
		case "provisioning_sessions":
			if remaining != 5 {
				t.Fatalf("remaining sessions=%d, want eligible parent held until its second attestation plus unresolved, recent-audit, exact-cutoff, and legal-hold sessions", remaining)
			}
		case "audit_events":
			if remaining != 1 {
				t.Fatalf("remaining audit events=%d, want recent event retained", remaining)
			}
		case "attestation_challenges":
			if remaining != 2 {
				t.Fatalf("remaining challenges=%d, want exact-cutoff and legal-hold challenges", remaining)
			}
		case "interswitch_webhook_events":
			if remaining != 0 {
				t.Fatalf("remaining webhook events=%d, want 0", remaining)
			}
		case "device_attestations":
			if remaining != 1 {
				t.Fatalf("remaining %s=%d, want one extra row beyond the per-invocation batch", table, remaining)
			}
		case "token_request_operations":
			if remaining != 1 {
				t.Fatalf("remaining token operations=%d, want unresolved operation", remaining)
			}
		}
	}
	secondCounts, err := postgres.NewSessionRepository(pool).PurgeExpired(ctx, now, policy, retention.Limits{BatchSize: 1})
	if err != nil {
		t.Fatalf("run second bounded purge: %v", err)
	}
	if secondCounts.DeviceAttestations != 1 || secondCounts.Sessions != 1 {
		t.Fatalf("second purge counts = %+v, want remaining child row then eligible parent", secondCounts)
	}
	var boundarySessionCount, boundaryChallengeCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM provisioning_sessions WHERE id=$1`, boundaryID).Scan(&boundarySessionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM attestation_challenges WHERE session_id=$1`, boundaryID).Scan(&boundaryChallengeCount); err != nil {
		t.Fatal(err)
	}
	if boundarySessionCount != 1 || boundaryChallengeCount != 1 {
		t.Fatalf("exact-cutoff rows deleted: session=%d challenge=%d; want both retained", boundarySessionCount, boundaryChallengeCount)
	}
	var heldSessionCount, heldChallengeCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM provisioning_sessions WHERE id=$1`, heldID).Scan(&heldSessionCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM attestation_challenges WHERE session_id=$1`, heldID).Scan(&heldChallengeCount); err != nil {
		t.Fatal(err)
	}
	if heldSessionCount != 1 || heldChallengeCount != 1 {
		t.Fatalf("held rows deleted: session=%d challenge=%d; want both retained", heldSessionCount, heldChallengeCount)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO provisioning_retention_holds (scope,reason_code,created_by) VALUES ('GLOBAL','LEGAL_HOLD','integration-test-operator')`); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.NewSessionRepository(pool).PurgeExpired(ctx, now.Add(100*24*time.Hour), policy, retention.Limits{BatchSize: 1}); !errors.Is(err, postgres.ErrPurgeGlobalHold) {
		t.Fatalf("global retention hold result=%v, want ErrPurgeGlobalHold", err)
	}
	var globalCounter int64
	if err := pool.QueryRow(ctx, `SELECT counter FROM device_attestation_counters WHERE provider='integration' AND key_id='globally-retained-key'`).Scan(&globalCounter); err != nil {
		t.Fatal(err)
	}
	if globalCounter != 8 {
		t.Fatalf("global replay counter=%d, want 8 after session purge", globalCounter)
	}
}
