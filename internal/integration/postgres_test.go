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
	if version != 18 {
		t.Fatalf("latest migration ledger version = %d, want 18", version)
	}
	var recorded int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version BETWEEN 1 AND 15`).Scan(&recorded); err != nil {
		t.Fatalf("count migration ledger baseline: %v", err)
	}
	if recorded != 15 {
		t.Fatalf("recorded migration baseline entries = %d, want 15", recorded)
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'provisioning_sessions' AND column_name IN ('version','token_reference','wrapped_payload','apdu_receipt','request_fingerprint')`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 5 {
		t.Fatalf("migration columns found = %d, want 5", columns)
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
	result, changed, err := repo.ReceiveTokenWebhook(ctx, semanticRetry, now.Add(2*time.Minute))
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

func TestPostgresExpiredWebhookRollsBackEventAtExpiryBoundary(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	expiresAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "expired-webhook-" + uuid.NewString(), UserID: "expired-webhook-owner", DeviceUID: "expired-webhook-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "nfc", State: domain.StateTokenRequested, TokenReference: "provider-reference-" + uuid.NewString(), Version: 1, Correlation: uuid.NewString(), CreatedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	event := domain.TokenWebhookEvent{EventID: "expired-event-" + uuid.NewString(), SessionID: session.ID, TokenReference: session.TokenReference}
	const deliveries = 12
	start := make(chan struct{})
	results := make(chan error, deliveries)
	var wg sync.WaitGroup
	for range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := repo.ReceiveTokenWebhook(ctx, event, expiresAt)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, domain.ErrSessionExpired) {
			t.Fatalf("expired concurrent delivery error = %v, want ErrSessionExpired", err)
		}
	}
	stored, err := repo.Get(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != domain.StateTokenRequested || stored.Version != 1 {
		t.Fatalf("expired callback mutated session: state=%s version=%d", stored.State, stored.Version)
	}
	var eventCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM interswitch_webhook_events WHERE session_id = $1`, session.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("expired callback persisted %d webhook events, want 0", eventCount)
	}
	requesting := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "expired-requesting-webhook-" + uuid.NewString(), UserID: "expired-requesting-owner", DeviceUID: "expired-requesting-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, Correlation: uuid.NewString(), CreatedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt}
	if _, created, err := repo.Create(ctx, requesting); err != nil || !created {
		t.Fatalf("create in-flight request session: created=%t err=%v", created, err)
	}
	if claim, err := repo.ClaimTokenRequest(ctx, requesting.ID, expiresAt.Add(-time.Nanosecond)); err != nil || !claim.Claimed {
		t.Fatalf("claim before expiry: claimed=%t err=%v", claim.Claimed, err)
	}
	lateEvent := domain.TokenWebhookEvent{EventID: "late-requesting-event-" + uuid.NewString(), SessionID: requesting.ID, TokenReference: "late-provider-reference"}
	if _, _, err := repo.ReceiveTokenWebhook(ctx, lateEvent, expiresAt); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("in-flight session exact-expiry callback error = %v, want ErrSessionExpired", err)
	}
	requestingStored, err := repo.Get(ctx, requesting.ID)
	if err != nil {
		t.Fatal(err)
	}
	if requestingStored.State != domain.StateTokenRequesting || requestingStored.Version != 2 {
		t.Fatalf("late in-flight callback changed session: state=%s version=%d", requestingStored.State, requestingStored.Version)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM interswitch_webhook_events WHERE session_id = $1`, requesting.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 0 {
		t.Fatalf("expired in-flight callback persisted %d webhook events, want 0", eventCount)
	}
}

func TestPostgresTokenRequestClaimIsAtomicAndCompletionIsIdempotent(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	now := time.Now().UTC()
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "token-claim-" + uuid.NewString(), UserID: "token-claim-owner", DeviceUID: "token-claim-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	const callers = 20
	start := make(chan struct{})
	claims := make(chan domain.TokenRequestClaim, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			claim, err := repo.ClaimTokenRequest(ctx, session.ID, now)
			if err != nil {
				errs <- err
				return
			}
			claims <- claim
		}()
	}
	close(start)
	wg.Wait()
	close(claims)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent token claim: %v", err)
	}
	claimCount := 0
	var stableKey string
	for claim := range claims {
		if claim.Claimed {
			claimCount++
		}
		if claim.Operation.Status != domain.TokenRequestPending {
			t.Fatalf("claim operation status = %s, want pending", claim.Operation.Status)
		}
		if stableKey == "" {
			stableKey = claim.Operation.IdempotencyKey
		}
		if claim.Operation.IdempotencyKey != stableKey {
			t.Fatalf("claim returned unstable provider key %q vs %q", claim.Operation.IdempotencyKey, stableKey)
		}
	}
	if claimCount != 1 || stableKey != domain.TokenRequestIdempotencyKey(session.ID) {
		t.Fatalf("durable claim winners=%d key=%q, want one winner and stable per-session key", claimCount, stableKey)
	}
	completed, changed, err := repo.CompleteTokenRequest(ctx, session.ID, "provider-reference-"+uuid.NewString(), now.Add(time.Second))
	if err != nil || !changed || completed.State != domain.StateTokenRequested {
		t.Fatalf("complete token operation: session=%+v changed=%t err=%v", completed, changed, err)
	}
	completedAgain, changed, err := repo.CompleteTokenRequest(ctx, session.ID, completed.TokenReference, now.Add(2*time.Second))
	if err != nil || changed || completedAgain.Version != completed.Version {
		t.Fatalf("idempotent completion changed state: session=%+v changed=%t err=%v", completedAgain, changed, err)
	}
	claim, err := repo.ClaimTokenRequest(ctx, session.ID, now.Add(2*time.Second))
	if err != nil || claim.Claimed || claim.Operation.Status != domain.TokenRequestSucceeded {
		t.Fatalf("completed operation was not idempotent: claim=%+v err=%v", claim, err)
	}
}

func TestPostgresUnknownTokenRequestCanBeResolvedByWebhook(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	now := time.Now().UTC()
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "token-unknown-" + uuid.NewString(), UserID: "token-unknown-owner", DeviceUID: "token-unknown-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "nfc", State: domain.StateSessionAuthenticated, Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	if claim, err := repo.ClaimTokenRequest(ctx, session.ID, now); err != nil || !claim.Claimed {
		t.Fatalf("claim token operation: claimed=%t err=%v", claim.Claimed, err)
	}
	unknown, err := repo.MarkTokenRequestUnknown(ctx, session.ID, "PROVIDER_CALL_OUTCOME_UNKNOWN", now.Add(time.Second))
	if err != nil || unknown.Operation.Status != domain.TokenRequestUnknown {
		t.Fatalf("mark ambiguous operation unknown: claim=%+v err=%v", unknown, err)
	}
	retry, err := repo.ClaimTokenRequest(ctx, session.ID, now.Add(2*time.Second))
	if err != nil || retry.Claimed || retry.Operation.Status != domain.TokenRequestUnknown {
		t.Fatalf("unknown operation was claimable again: claim=%+v err=%v", retry, err)
	}
	event := domain.TokenWebhookEvent{EventID: "resolve-event-" + uuid.NewString(), SessionID: session.ID, TokenReference: "resolved-provider-reference"}
	resolved, changed, err := repo.ReceiveTokenWebhook(ctx, event, now.Add(3*time.Second))
	if err != nil || !changed || resolved.State != domain.StateTokenReceived || resolved.TokenReference != event.TokenReference {
		t.Fatalf("webhook did not resolve unknown operation: session=%+v changed=%t err=%v", resolved, changed, err)
	}
	var status, providerReference string
	if err := pool.QueryRow(ctx, `SELECT status, provider_reference FROM token_request_operations WHERE session_id = $1`, session.ID).Scan(&status, &providerReference); err != nil {
		t.Fatal(err)
	}
	if status != string(domain.TokenRequestSucceeded) || providerReference != event.TokenReference {
		t.Fatalf("persisted operation status/reference = %q/%q, want succeeded/%q", status, providerReference, event.TokenReference)
	}
}

func TestPostgresLateProviderSuccessIsRecordedWithoutAdvancingExpiredSession(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewSessionRepository(pool)
	now := time.Now().UTC()
	expiresAt := now.Add(time.Minute)
	session := domain.ProvisioningSession{ID: uuid.NewString(), IdempotencyKey: "late-provider-success-" + uuid.NewString(), UserID: "late-provider-owner", DeviceUID: "late-provider-device-" + uuid.NewString(), DeviceModel: "integration-hardware", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, Correlation: uuid.NewString(), CreatedAt: now, ExpiresAt: expiresAt}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	if claim, err := repo.ClaimTokenRequest(ctx, session.ID, now); err != nil || !claim.Claimed {
		t.Fatalf("claim before expiry: claimed=%t err=%v", claim.Claimed, err)
	}
	providerReference := "late-provider-reference-" + uuid.NewString()
	updated, changed, err := repo.CompleteTokenRequest(ctx, session.ID, providerReference, expiresAt)
	if !errors.Is(err, domain.ErrSessionExpired) || changed {
		t.Fatalf("late completion: changed=%t err=%v, want no transition and ErrSessionExpired", changed, err)
	}
	if updated.State != domain.StateTokenRequesting || updated.Version != 2 || updated.TokenReference != "" {
		t.Fatalf("late provider result advanced the expired session: %+v", updated)
	}
	var status, storedReference string
	if err := pool.QueryRow(ctx, `SELECT status, provider_reference FROM token_request_operations WHERE session_id = $1`, session.ID).Scan(&status, &storedReference); err != nil {
		t.Fatal(err)
	}
	if status != string(domain.TokenRequestSucceeded) || storedReference != providerReference {
		t.Fatalf("late provider result not recorded for reconciliation: status=%q reference=%q", status, storedReference)
	}
}
