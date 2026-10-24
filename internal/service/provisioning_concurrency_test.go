package service

import (
	"context"
	"sync"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
)

func TestCreateIsAtomicForConcurrentIdempotencyKey(t *testing.T) {
	svc := New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	input := CreateInput{UserID: "u-concurrent", DeviceUID: "d-concurrent", DeviceModel: "wearable-v1", Transport: "ble"}
	const callers = 24
	results := make(chan string, callers)
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, _, err := svc.Create(context.Background(), input, "same-key")
			if err != nil {
				errors <- err
				return
			}
			results <- s.ID
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var first string
	for id := range results {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatalf("expected one session ID, got %s and %s", first, id)
		}
	}
}
