package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/registry"
)

func TestDeviceRegistryBindsOwnershipAndRotatesKeys(t *testing.T) {
	repo := NewDeviceRegistry()
	now := time.Unix(100, 0)
	device, err := repo.EnsureDevice(context.Background(), "user-a", "physical-device-a", "model-a", "ble", now)
	if err != nil {
		t.Fatal(err)
	}
	if device.State != registry.StatePending || device.ID == "" {
		t.Fatalf("unexpected pending device: %+v", device)
	}
	if _, err := repo.EnsureDevice(context.Background(), "user-b", "physical-device-a", "model-a", "ble", now); !errors.Is(err, registry.ErrDeviceAlreadyOwned) {
		t.Fatalf("expected cross-user ownership rejection, got %v", err)
	}
	keyOne := registry.KeyMetadata{Provider: "apple-app-attest", KeyID: "key-one", PublicKeyDER: []byte("key-one-public"), Counter: 0}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, keyOne.Provider, keyOne.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := repo.RegisterAttestation(context.Background(), "user-a", device.ID, keyOne, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, keyOne.Provider, keyOne.KeyID); err != nil {
		t.Fatal(err)
	}
	keyTwo := registry.KeyMetadata{Provider: "apple-app-attest", KeyID: "key-two", PublicKeyDER: []byte("key-two-public"), Counter: 0}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, keyTwo.Provider, keyTwo.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := repo.RegisterAttestation(context.Background(), "user-a", device.ID, keyTwo, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, keyOne.Provider, keyOne.KeyID); !errors.Is(err, registry.ErrKeyReplaced) {
		t.Fatalf("expected rotated key rejection, got %v", err)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, keyTwo.Provider, keyTwo.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := repo.RegisterAttestation(context.Background(), "user-a", device.ID, registry.KeyMetadata{Provider: keyTwo.Provider, KeyID: keyTwo.KeyID, Counter: 0}, now.Add(2*time.Minute)); !errors.Is(err, registry.ErrCounterRollback) {
		t.Fatalf("expected counter rollback rejection, got %v", err)
	}
}

func TestDeviceRegistryRevocationAndReplacement(t *testing.T) {
	repo := NewDeviceRegistry()
	now := time.Unix(200, 0)
	device, err := repo.EnsureDevice(context.Background(), "user-a", "physical-device-b", "model-a", "nfc", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RegisterAttestation(context.Background(), "user-a", device.ID, registry.KeyMetadata{Provider: "provider", KeyID: "key", Counter: 0}, now); err != nil {
		t.Fatal(err)
	}
	replacement, err := repo.ReplaceDevice(context.Background(), "user-a", device.ID, "physical-device-c", "model-b", "ble", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if replacement.State != registry.StatePending || replacement.ID == device.ID {
		t.Fatalf("unexpected replacement: %+v", replacement)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, "provider", "key"); !errors.Is(err, registry.ErrDeviceUnavailable) {
		t.Fatalf("expected replaced device rejection, got %v", err)
	}
	if err := repo.RevokeDevice(context.Background(), "user-a", replacement.ID, "lost", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", replacement.ID, "provider", "new-key"); !errors.Is(err, registry.ErrDeviceUnavailable) {
		t.Fatalf("expected revoked device rejection, got %v", err)
	}
}

func TestDeviceRegistryLifecycleTransitions(t *testing.T) {
	repo := NewDeviceRegistry()
	now := time.Unix(300, 0)
	device, err := repo.EnsureDevice(context.Background(), "user-a", "physical-device-d", "model-a", "ble", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.RegisterAttestation(context.Background(), "user-a", device.ID, registry.KeyMetadata{Provider: "provider", KeyID: "key", Counter: 0}, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetLifecycle(context.Background(), "user-a", device.ID, registry.StateSuspended, "maintenance", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.AuthorizeAttestation(context.Background(), "user-a", device.ID, "provider", "key"); !errors.Is(err, registry.ErrDeviceUnavailable) {
		t.Fatalf("expected suspended device rejection, got %v", err)
	}
	if err := repo.SetLifecycle(context.Background(), "user-a", device.ID, registry.StateActive, "restored", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetLifecycle(context.Background(), "user-a", device.ID, registry.StateRetired, "decommissioned", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetLifecycle(context.Background(), "user-a", device.ID, registry.StateActive, "invalid", now.Add(4*time.Minute)); !errors.Is(err, registry.ErrInvalidLifecycle) {
		t.Fatalf("expected retired transition rejection, got %v", err)
	}
}
