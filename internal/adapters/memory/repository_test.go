package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/domain"
)

func TestSessionSaveUsesCompareAndSwapVersion(t *testing.T) {
	repo := NewSessionRepository()
	created := domain.ProvisioningSession{ID: "session-1", IdempotencyKey: "idem-1", UserID: "user-1", DeviceUID: "device-1", DeviceModel: "wearable", Transport: "ble", State: domain.StateCreated}
	stored, createdNew, err := repo.Create(context.Background(), created)
	if err != nil || !createdNew {
		t.Fatalf("create failed: created=%v err=%v", createdNew, err)
	}
	if stored.Version != 1 {
		t.Fatalf("initial version = %d, want 1", stored.Version)
	}

	writerA, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	writerB, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := writerA.Transition(domain.StateDeviceDiscovered); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.Save(context.Background(), writerA)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.State != domain.StateDeviceDiscovered {
		t.Fatalf("updated session = %+v, want version 2 and discovered state", updated)
	}

	if err := writerB.Transition(domain.StateFailed); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Save(context.Background(), writerB); !errors.Is(err, domain.ErrConcurrentUpdate) {
		t.Fatalf("stale save error = %v, want concurrent update", err)
	}
	final, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != domain.StateDeviceDiscovered || final.Version != 2 {
		t.Fatalf("stale writer changed session: %+v", final)
	}
}

func TestConcurrentSessionSavesHaveSingleWinner(t *testing.T) {
	repo := NewSessionRepository()
	created, _, err := repo.Create(context.Background(), domain.ProvisioningSession{ID: "session-race", IdempotencyKey: "idem-race", UserID: "user-1", DeviceUID: "device-1", DeviceModel: "wearable", Transport: "ble", State: domain.StateCreated})
	if err != nil {
		t.Fatal(err)
	}
	const writers = 32
	var wg sync.WaitGroup
	results := make(chan error, writers)
	for i := 0; i < writers; i++ {
		writer := created
		if err := writer.Transition(domain.StateDeviceDiscovered); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, saveErr := repo.Save(context.Background(), writer)
			results <- saveErr
		}()
	}
	wg.Wait()
	close(results)

	wins, conflicts := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, domain.ErrConcurrentUpdate) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent save error: %v", err)
		}
	}
	if wins != 1 || conflicts != writers-1 {
		t.Fatalf("concurrent saves: wins=%d conflicts=%d, want 1 and %d", wins, conflicts, writers-1)
	}
	final, err := repo.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.State != domain.StateDeviceDiscovered || final.Version != 2 {
		t.Fatalf("final session = %+v, want discovered at version 2", final)
	}
}

func TestWebhookEventDedupeIsIdempotentAndRejectsIDReuse(t *testing.T) {
	repo := NewSessionRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	session := domain.ProvisioningSession{ID: "session-webhook", IdempotencyKey: "idem-webhook", UserID: "user-webhook", DeviceUID: "device-webhook", DeviceModel: "device-model", Transport: "nfc", State: domain.StateTokenRequested, TokenReference: "provider-reference", Version: 1}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create prerequisite session: created=%t err=%v", created, err)
	}
	event := domain.TokenWebhookEvent{EventID: "provider-event-1", SessionID: session.ID, TokenReference: session.TokenReference}
	first, changed, err := repo.ReceiveTokenWebhook(ctx, event, now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first webhook delivery did not report a transition")
	}
	if first.State != domain.StateTokenReceived || first.Version != 2 {
		t.Fatalf("first delivery = state %s version %d; want received/version 2", first.State, first.Version)
	}
	retry, changed, err := repo.ReceiveTokenWebhook(ctx, event, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("duplicate event reported a second transition")
	}
	if retry.State != first.State || retry.Version != first.Version {
		t.Fatalf("same event changed state/version: first=%+v retry=%+v", first, retry)
	}

	semanticRetry := event
	semanticRetry.EventID = "provider-event-retry"
	semantic, changed, err := repo.ReceiveTokenWebhook(ctx, semanticRetry, now.Add(2*time.Second))
	if err != nil || semantic.Version != first.Version {
		t.Fatalf("same signed semantic payload was not idempotent: session=%+v err=%v", semantic, err)
	}
	if changed {
		t.Fatal("semantic duplicate reported a second transition")
	}

	reusedID := event
	reusedID.TokenReference = "different-reference"
	if _, _, err := repo.ReceiveTokenWebhook(ctx, reusedID, now.Add(3*time.Second)); !errors.Is(err, domain.ErrWebhookEventConflict) {
		t.Fatalf("event ID reuse error = %v, want content conflict", err)
	}
}
