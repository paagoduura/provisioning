package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
)

func TestSaveAttestationIfCounterAdvancesIsAtomic(t *testing.T) {
	repo := NewAttestationRepository()
	const submissions = 100
	var wg sync.WaitGroup
	for counter := uint64(1); counter <= submissions; counter++ {
		wg.Add(1)
		go func(counter uint64) {
			defer wg.Done()
			_, err := repo.SaveAttestationIfCounterAdvances(context.Background(), "session-1", attestation.VerifiedResult{
				Provider: "test-provider",
				KeyID:    "key-1",
				Counter:  counter,
			}, time.Now())
			if err != nil {
				t.Errorf("save counter %d: %v", counter, err)
			}
		}(counter)
	}
	wg.Wait()

	accepted, err := repo.SaveAttestationIfCounterAdvances(context.Background(), "session-2", attestation.VerifiedResult{
		Provider: "test-provider",
		KeyID:    "key-1",
		Counter:  submissions - 1,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Fatal("stale counter was accepted after concurrent updates")
	}
}
