//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/migrations"
)

// These tests require an actual PostgreSQL server. Each test run owns an
// ephemeral schema and never drops or mutates objects in the caller's schema.
func openPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("set DATABASE_URL to a disposable real PostgreSQL database to run integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	t.Cleanup(admin.Close)
	schema := "it_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+pgxIdentifier(schema)); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA `+pgxIdentifier(schema)+` CASCADE`) })
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to isolated schema: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, ctx
}

func pgxIdentifier(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func applyMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("apply embedded PostgreSQL migrations: %v", err)
	}
}

func TestMigrationsApplyInOrderAndAreReplayable(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	applyMigrations(t, ctx, pool)
	var version int64
	if err := pool.QueryRow(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read migration ledger: %v", err)
	}
	if version != 14 {
		t.Fatalf("latest migration ledger version = %d, want 14", version)
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name IN ('version','token_reference','wrapped_payload','apdu_receipt')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 4 {
		t.Fatalf("migration columns found = %d, want 4", columns)
	}
}

func TestPostgresConcurrentIdempotencyAndCAS(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	now := time.Now().UTC()
	base := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "request-" + uuid.NewString(), UserID: "real-row-test-user", DeviceUID: "device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "ble", State: domain.StateCreated, Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	const callers = 20
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := base
			candidate.ID = uuid.NewString()
			candidate.Correlation = uuid.NewString()
			got, _, err := repo.Create(ctx, candidate)
			if err != nil {
				errs <- err
				return
			}
			ids <- got.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Create: %v", err)
	}
	var canonical string
	for id := range ids {
		if canonical == "" {
			canonical = id
		}
		if id != canonical {
			t.Fatalf("idempotency produced IDs %s and %s", canonical, id)
		}
	}

	stale, err := repo.Get(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 2
	start := make(chan struct{})
	results := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := stale
			s.State = domain.StateDeviceDiscovered
			<-start
			_, err := repo.Save(ctx, s)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, domain.ErrConcurrentUpdate) {
			conflict++
		} else {
			t.Fatalf("unexpected CAS error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("CAS outcomes: success=%d conflict=%d, want 1/1", success, conflict)
	}
	final, err := repo.Get(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 2 || final.State != domain.StateDeviceDiscovered {
		t.Fatalf("persisted winner = state %q version %d", final.State, final.Version)
	}
}

func TestPostgresChallengeCanBeConsumedOnlyOnce(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	now := time.Now().UTC()
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "challenge-" + uuid.NewString(), UserID: "challenge-owner", DeviceUID: "challenge-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "nfc", State: domain.StateCreated, Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, created, err := postgres.NewSessionRepository(pool).Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	challenge := attestation.Challenge{ID: uuid.NewString(), SessionID: session.ID, Value: uuid.NewString(), RequestHash: "server-issued-digest", RequestDocument: []byte(`{"operation":"provision"}`), ExpiresAt: now.Add(time.Minute)}
	repo := postgres.NewAttestationRepository(pool)
	if err := repo.Create(ctx, challenge); err != nil {
		t.Fatalf("create challenge in PostgreSQL: %v", err)
	}
	const consumers = 16
	start := make(chan struct{})
	results := make(chan error, consumers)
	var wg sync.WaitGroup
	for range consumers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := repo.Consume(ctx, challenge.ID, time.Now().UTC())
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, replayFailures := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, attestation.ErrChallengeUsed) {
			replayFailures++
		} else {
			t.Fatalf("unexpected challenge consume error: %v", err)
		}
	}
	if successes != 1 || replayFailures != consumers-1 {
		t.Fatalf("challenge consume outcomes: success=%d replay=%d, want 1/%d", successes, replayFailures, consumers-1)
	}
}

func TestPostgresWebhookDeduplicationIsAtomicUnderConcurrency(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	now := time.Now().UTC()
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "webhook-" + uuid.NewString(), UserID: "webhook-integration-owner", DeviceUID: "webhook-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "nfc", State: domain.StateTokenRequested, TokenReference: "provider-reference-" + uuid.NewString(), Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	event := domain.TokenWebhookEvent{EventID: "provider-event-" + uuid.NewString(), SessionID: session.ID, TokenReference: session.TokenReference}
	const deliveries = 20
	type deliveryResult struct {
		session domain.ProvisioningSession
		changed bool
	}
	start := make(chan struct{})
	results := make(chan deliveryResult, deliveries)
	errs := make(chan error, deliveries)
	var wg sync.WaitGroup
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, changed, err := repo.ReceiveTokenWebhook(ctx, event, time.Now().UTC())
			if err != nil {
				errs <- err
				return
			}
			results <- deliveryResult{session: result, changed: changed}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent webhook delivery: %v", err)
	}
	transitions := 0
	for result := range results {
		if result.session.State != domain.StateTokenReceived || result.session.Version != 2 {
			t.Fatalf("concurrent delivery returned state %s version %d; want received/version 2", result.session.State, result.session.Version)
		}
		if result.changed {
			transitions++
		}
	}
	if transitions != 1 {
		t.Fatalf("concurrent webhook deliveries advanced state %d times, want 1", transitions)
	}

	semanticRetry := event
	semanticRetry.EventID = "provider-retry-" + uuid.NewString()
	result, changed, err := repo.ReceiveTokenWebhook(ctx, semanticRetry, time.Now().UTC())
	if err != nil || result.Version != 2 || changed {
		t.Fatalf("same semantic delivery was not idempotent: session=%+v err=%v", result, err)
	}
	reusedID := event
	reusedID.TokenReference = "different-reference"
	if _, _, err := repo.ReceiveTokenWebhook(ctx, reusedID, time.Now().UTC()); !errors.Is(err, domain.ErrWebhookEventConflict) {
		t.Fatalf("event ID reuse error = %v, want content conflict", err)
	}
	var recorded int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM interswitch_webhook_events WHERE session_id = $1`, session.ID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Fatalf("persisted matching webhook fingerprints = %d, want 1", recorded)
	}
}

func TestPostgresRejectsInvalidPersistedTransport(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	now := time.Now().UTC()
	_, err := pool.Exec(ctx, `INSERT INTO provisioning_sessions (id,idempotency_key,user_id,device_uid_hash,device_model,transport,state,correlation_id,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, uuid.NewString(), uuid.NewString(), "constraint-test", []byte("hash"), "device", "invalid-transport", "CREATED", uuid.NewString(), now, now.Add(time.Minute))
	if err == nil {
		t.Fatal("PostgreSQL accepted an invalid transport; expected CHECK constraint failure")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "check constraint") {
		t.Fatalf("expected real CHECK constraint failure, got %v", err)
	}
}
