package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

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
