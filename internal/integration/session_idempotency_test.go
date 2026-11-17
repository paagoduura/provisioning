//go:build integration

package integration

import (
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/internal/service"
)

func TestPostgresSessionIdempotencyFingerprintResolvesBeforeRegistrySideEffects(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	sessionRepo := postgres.NewSessionRepository(pool)
	deviceRepo := postgres.NewDeviceRegistry(pool)
	provisioning := service.New(sessionRepo, nil, nil, nil)
	provisioning.SetDeviceRegistry(deviceRepo)

	inputs := []service.CreateInput{
		{UserID: "fingerprint-owner", DeviceUID: "fingerprint-device-a", DeviceModel: "model-a", Transport: "ble"},
		{UserID: "fingerprint-owner", DeviceUID: "fingerprint-device-b", DeviceModel: "model-b", Transport: "nfc"},
	}
	const idempotencyKey = "concurrent-fingerprint-race"
	type result struct {
		session domain.ProvisioningSession
		replay  bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, len(inputs))
	var wg sync.WaitGroup
	for _, input := range inputs {
		input := input
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			session, replay, err := provisioning.Create(ctx, input, idempotencyKey)
			results <- result{session: session, replay: replay, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var winner domain.ProvisioningSession
	created, conflicts := 0, 0
	for got := range results {
		switch {
		case got.err == nil:
			created++
			winner = got.session
		case errors.Is(got.err, domain.ErrIdempotencyConflict):
			conflicts++
		default:
			t.Fatalf("concurrent create error=%v", got.err)
		}
	}
	if created != 1 || conflicts != 1 || winner.ID == "" || winner.DeviceID == "" || winner.Version < 2 {
		t.Fatalf("same-key create outcomes created=%d conflicts=%d winner=%+v, want one created session with persisted device link", created, conflicts, winner)
	}

	hashA := sha256.Sum256([]byte(inputs[0].DeviceUID))
	hashB := sha256.Sum256([]byte(inputs[1].DeviceUID))
	var sideEffectCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_devices WHERE device_uid_hash IN ($1, $2)`, hashA[:], hashB[:]).Scan(&sideEffectCount); err != nil {
		t.Fatal(err)
	}
	if sideEffectCount != 1 {
		t.Fatalf("registered-device rows for colliding idempotency key = %d, want exactly one", sideEffectCount)
	}
	var fingerprint []byte
	if err := pool.QueryRow(ctx, `SELECT request_fingerprint FROM provisioning_sessions WHERE id = $1`, winner.ID).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != sha256.Size {
		t.Fatalf("persisted request fingerprint length = %d, want %d", len(fingerprint), sha256.Size)
	}

	winnerInput := inputs[0]
	if winner.DeviceUID == inputs[1].DeviceUID {
		winnerInput = inputs[1]
	}
	replayed, isReplay, err := provisioning.Create(ctx, winnerInput, idempotencyKey)
	if err != nil || !isReplay || replayed.ID != winner.ID || replayed.DeviceID != winner.DeviceID || replayed.DeviceUID != winnerInput.DeviceUID {
		t.Fatalf("same-payload retry: session=%+v replay=%t err=%v", replayed, isReplay, err)
	}

	var afterRetry int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_devices WHERE device_uid_hash IN ($1, $2)`, hashA[:], hashB[:]).Scan(&afterRetry); err != nil {
		t.Fatal(err)
	}
	if afterRetry != 1 {
		t.Fatalf("same-payload retry created additional registered devices: count=%d", afterRetry)
	}
}

func TestPostgresLegacyIdempotencyKeyWithoutFingerprintFailsClosed(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	sessionRepo := postgres.NewSessionRepository(pool)
	deviceRepo := postgres.NewDeviceRegistry(pool)
	provisioning := service.New(sessionRepo, nil, nil, nil)
	provisioning.SetDeviceRegistry(deviceRepo)
	now := time.Now().UTC()
	legacy := domain.ProvisioningSession{ID: "legacy-idempotency-session", IdempotencyKey: "legacy-idempotency-key", UserID: "legacy-owner", DeviceUID: "legacy-device", DeviceModel: "legacy-model", Transport: "ble", State: domain.StateCreated, Version: 1, Correlation: "legacy-correlation", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if _, created, err := sessionRepo.Create(ctx, legacy); err != nil || !created {
		t.Fatalf("create legacy session: created=%t err=%v", created, err)
	}
	_, _, err := provisioning.Create(ctx, service.CreateInput{UserID: legacy.UserID, DeviceUID: legacy.DeviceUID, DeviceModel: legacy.DeviceModel, Transport: legacy.Transport}, legacy.IdempotencyKey)
	if !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("legacy retry error=%v, want fail-closed idempotency conflict", err)
	}
	hash := sha256.Sum256([]byte(legacy.DeviceUID))
	var registryRows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_devices WHERE device_uid_hash = $1`, hash[:]).Scan(&registryRows); err != nil {
		t.Fatal(err)
	}
	if registryRows != 0 {
		t.Fatalf("legacy idempotency replay caused %d registry side effects, want 0", registryRows)
	}
}

func TestPostgresConcurrentSamePayloadSessionCreationReturnsOneBoundSession(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	provisioning := service.New(postgres.NewSessionRepository(pool), nil, nil, nil)
	provisioning.SetDeviceRegistry(postgres.NewDeviceRegistry(pool))
	input := service.CreateInput{UserID: "same-payload-owner", DeviceUID: "same-payload-device", DeviceModel: "secure-device", Transport: "nfc"}
	const callers = 16
	start := make(chan struct{})
	type createResult struct {
		session domain.ProvisioningSession
		replay  bool
		err     error
	}
	results := make(chan createResult, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			session, replay, err := provisioning.Create(ctx, input, "same-payload-concurrent-key")
			results <- createResult{session: session, replay: replay, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var sessionID, deviceID string
	created, replays := 0, 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("same-payload concurrent create: %v", result.err)
		}
		if result.session.ID == "" || result.session.DeviceID == "" || result.session.DeviceUID != input.DeviceUID {
			t.Fatalf("incomplete concurrent create response: %+v", result.session)
		}
		if sessionID == "" {
			sessionID, deviceID = result.session.ID, result.session.DeviceID
		}
		if result.session.ID != sessionID || result.session.DeviceID != deviceID {
			t.Fatalf("concurrent callers received different bindings: first=%s/%s got=%s/%s", sessionID, deviceID, result.session.ID, result.session.DeviceID)
		}
		if result.replay {
			replays++
		} else {
			created++
		}
	}
	if created != 1 || replays != callers-1 {
		t.Fatalf("concurrent create outcomes created=%d replay=%d, want 1/%d", created, replays, callers-1)
	}
	hash := sha256.Sum256([]byte(input.DeviceUID))
	var sessionRows, deviceRows int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM provisioning_sessions WHERE idempotency_key = $1`, "same-payload-concurrent-key").Scan(&sessionRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_devices WHERE device_uid_hash = $1`, hash[:]).Scan(&deviceRows); err != nil {
		t.Fatal(err)
	}
	if sessionRows != 1 || deviceRows != 1 {
		t.Fatalf("persisted concurrent creation rows: sessions=%d devices=%d, want 1/1", sessionRows, deviceRows)
	}
}
