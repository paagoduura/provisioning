package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/domain"
)

func TestCreateBindsIdempotencyKeyToRequestFingerprint(t *testing.T) {
	repo := NewSessionRepository()
	ctx := context.Background()
	first := domain.ProvisioningSession{ID: "session-fingerprint-1", IdempotencyKey: "fingerprint-key", RequestFingerprint: make([]byte, 32), UserID: "owner", DeviceUID: "device-a", DeviceModel: "model", Transport: "ble", State: domain.StateCreated, Version: 1, CreatedAt: time.Now().UTC()}
	first.RequestFingerprint[0] = 0x1
	stored, created, err := repo.Create(ctx, first)
	if err != nil || !created || stored.ID != first.ID {
		t.Fatalf("initial create: stored=%+v created=%t err=%v", stored, created, err)
	}

	retry := first
	retry.ID = "session-fingerprint-retry"
	replayed, created, err := repo.Create(ctx, retry)
	if err != nil || created || replayed.ID != first.ID {
		t.Fatalf("same-fingerprint retry: session=%+v created=%t err=%v", replayed, created, err)
	}

	changed := retry
	changed.RequestFingerprint = append([]byte(nil), first.RequestFingerprint...)
	changed.RequestFingerprint[0] ^= 0xff
	if _, _, err := repo.Create(ctx, changed); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("changed-fingerprint retry error=%v, want idempotency conflict", err)
	}
}

func TestLegacyIdempotencyRecordCannotMatchFingerprintedRequest(t *testing.T) {
	repo := NewSessionRepository()
	ctx := context.Background()
	legacy := domain.ProvisioningSession{ID: "legacy-session", IdempotencyKey: "legacy-key", UserID: "owner", DeviceUID: "device", DeviceModel: "model", Transport: "nfc", State: domain.StateCreated, Version: 1}
	if _, created, err := repo.Create(ctx, legacy); err != nil || !created {
		t.Fatalf("legacy create: created=%t err=%v", created, err)
	}
	newRequest := legacy
	newRequest.ID = "new-session"
	newRequest.RequestFingerprint = make([]byte, 32)
	newRequest.RequestFingerprint[0] = 1
	if _, _, err := repo.Create(ctx, newRequest); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("legacy fingerprint retry error=%v, want fail-closed idempotency conflict", err)
	}
}
