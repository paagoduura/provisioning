//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/postgres"
	"github.com/paagoduura/provisioning/internal/registry"
)

func TestPostgresConcurrentDeviceRegistrationIsIdempotent(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewDeviceRegistry(pool)
	now := time.Now().UTC()
	const callers = 20
	start := make(chan struct{})
	ids := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			device, err := repo.EnsureDevice(ctx, "registry-owner", "registration-race-device", "integration-hardware", "ble", now)
			if err != nil {
				errs <- err
				return
			}
			ids <- device.ID
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent EnsureDevice: %v", err)
	}
	var canonicalID string
	for id := range ids {
		if canonicalID == "" {
			canonicalID = id
		}
		if id != canonicalID {
			t.Fatalf("concurrent registration returned device IDs %q and %q", canonicalID, id)
		}
	}
	var count int
	hash := sha256.Sum256([]byte("registration-race-device"))
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_devices WHERE device_uid_hash = $1`, hash[:]).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("persisted rows for raced registration = %d, want 1", count)
	}
}

func TestPostgresConcurrentCrossOwnerDeviceRegistrationHasSingleOwner(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewDeviceRegistry(pool)
	now := time.Now().UTC()
	const callers = 12
	start := make(chan struct{})
	owners := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for index := range callers {
		owner := fmt.Sprintf("contending-owner-%d", index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			device, err := repo.EnsureDevice(ctx, owner, "cross-owner-registration-race", "integration-hardware", "ble", now)
			if errors.Is(err, registry.ErrDeviceAlreadyOwned) {
				return
			}
			if err != nil {
				errs <- err
				return
			}
			owners <- device.UserID
		}()
	}
	close(start)
	wg.Wait()
	close(owners)
	close(errs)
	for err := range errs {
		t.Fatalf("cross-owner EnsureDevice: %v", err)
	}
	var winningOwner string
	winners := 0
	for owner := range owners {
		winners++
		winningOwner = owner
	}
	if winners != 1 || winningOwner == "" {
		t.Fatalf("concurrent registration winners = %d owner=%q, want exactly one owner", winners, winningOwner)
	}
	var persistedOwner string
	hash := sha256.Sum256([]byte("cross-owner-registration-race"))
	if err := pool.QueryRow(ctx, `SELECT user_id FROM registered_devices WHERE device_uid_hash = $1`, hash[:]).Scan(&persistedOwner); err != nil {
		t.Fatal(err)
	}
	if persistedOwner != winningOwner {
		t.Fatalf("persisted owner=%q, successful caller owner=%q", persistedOwner, winningOwner)
	}
}

func TestPostgresCompetingDeviceReplacementsHaveOneWinner(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewDeviceRegistry(pool)
	now := time.Now().UTC()
	old, err := repo.EnsureDevice(ctx, "replace-owner", "replace-old-device", "old-model", "ble", now)
	if err != nil {
		t.Fatal(err)
	}
	registerIntegrationKey(t, ctx, repo, "replace-owner", old.ID, "replace-old-key", 1, now)

	const callers = 2
	start := make(chan struct{})
	results := make(chan registry.Device, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for index := range callers {
		uid := fmt.Sprintf("replacement-candidate-%d", index)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			device, replaceErr := repo.ReplaceDevice(ctx, "replace-owner", old.ID, uid, "replacement-model", "nfc", now.Add(time.Second))
			if replaceErr != nil {
				errs <- replaceErr
				return
			}
			results <- device
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	replacementConflicts := 0
	for err := range errs {
		if !errors.Is(err, registry.ErrDeviceUnavailable) {
			t.Fatalf("losing replacement error=%v, want unavailable old device", err)
		}
		replacementConflicts++
	}
	var winner registry.Device
	replacementWinners := 0
	for device := range results {
		replacementWinners++
		winner = device
	}
	if replacementWinners != 1 || replacementConflicts != 1 || winner.ID == "" {
		t.Fatalf("competing replacement outcomes winners=%d conflicts=%d, want 1/1", replacementWinners, replacementConflicts)
	}
	oldStored, err := repo.GetDevice(ctx, "replace-owner", old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldStored.State != registry.StateReplaced || oldStored.ReplacedByID != winner.ID {
		t.Fatalf("old device replacement linkage = state %s replaced_by %q, want %s/%s", oldStored.State, oldStored.ReplacedByID, registry.StateReplaced, winner.ID)
	}
	if !registry.IsUsable(winner.State) {
		t.Fatalf("replacement winner state=%s, expected usable pending/active state", winner.State)
	}
	var activeOldKeys int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_device_attestations WHERE device_id = $1 AND lifecycle_state = $2`, old.ID, registry.StateActive).Scan(&activeOldKeys); err != nil {
		t.Fatal(err)
	}
	if activeOldKeys != 0 {
		t.Fatalf("replaced device retains %d active attestation keys", activeOldKeys)
	}
}

func TestPostgresDeviceRevocationSerializesWithSuspension(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewDeviceRegistry(pool)
	now := time.Now().UTC()
	device, err := repo.EnsureDevice(ctx, "lifecycle-owner", "lifecycle-race-device", "integration-hardware", "ble", now)
	if err != nil {
		t.Fatal(err)
	}
	registerIntegrationKey(t, ctx, repo, "lifecycle-owner", device.ID, "lifecycle-race-key", 1, now)

	start := make(chan struct{})
	type lifecycleResult struct {
		operation string
		err       error
	}
	results := make(chan lifecycleResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		results <- lifecycleResult{operation: "suspend", err: repo.SetLifecycle(ctx, "lifecycle-owner", device.ID, registry.StateSuspended, "concurrency test", now.Add(time.Second))}
	}()
	go func() {
		defer wg.Done()
		<-start
		results <- lifecycleResult{operation: "revoke", err: repo.RevokeDevice(ctx, "lifecycle-owner", device.ID, "concurrency test", now.Add(time.Second))}
	}()
	close(start)
	wg.Wait()
	close(results)
	successfulSuspends, invalidSuspends, successfulRevocations := 0, 0, 0
	for result := range results {
		switch result.operation {
		case "suspend":
			if result.err == nil {
				successfulSuspends++
			} else if errors.Is(result.err, registry.ErrInvalidLifecycle) {
				invalidSuspends++
			} else {
				t.Fatalf("concurrent suspend error=%v", result.err)
			}
		case "revoke":
			if result.err != nil {
				t.Fatalf("concurrent revoke error=%v", result.err)
			}
			successfulRevocations++
		}
	}
	if successfulRevocations != 1 || successfulSuspends+invalidSuspends != 1 {
		t.Fatalf("suspend/revoke outcomes: successful_suspend=%d invalid_suspend=%d successful_revoke=%d", successfulSuspends, invalidSuspends, successfulRevocations)
	}
	stored, err := repo.GetDevice(ctx, "lifecycle-owner", device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != registry.StateRevoked {
		t.Fatalf("final device state=%s, want revoked", stored.State)
	}
	var activeKeys, revocationRecords int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM registered_device_attestations WHERE device_id = $1 AND lifecycle_state = $2`, device.ID, registry.StateActive).Scan(&activeKeys); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_key_revocations WHERE key_id = $1`, "lifecycle-race-key").Scan(&revocationRecords); err != nil {
		t.Fatal(err)
	}
	if activeKeys != 0 || revocationRecords != 1 {
		t.Fatalf("revocation invariants: active_keys=%d revocation_records=%d, want 0/1", activeKeys, revocationRecords)
	}
}

func TestPostgresAttestationKeyBindingAndRotationAreSerialized(t *testing.T) {
	pool, ctx := openPostgres(t)
	applyMigrations(t, ctx, pool)
	repo := postgres.NewDeviceRegistry(pool)
	now := time.Now().UTC()
	firstDevice, err := repo.EnsureDevice(ctx, "key-owner", "key-race-device-1", "integration-hardware", "ble", now)
	if err != nil {
		t.Fatal(err)
	}
	secondDevice, err := repo.EnsureDevice(ctx, "key-owner", "key-race-device-2", "integration-hardware", "ble", now)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	contestedKey := testKey(t, "global-key-contested", 1)
	for _, device := range []registry.Device{firstDevice, secondDevice} {
		device := device
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- repo.RegisterAttestation(ctx, "key-owner", device.ID, contestedKey, now.Add(time.Second))
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, keyConflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, registry.ErrKeyBoundElsewhere):
			keyConflicts++
		default:
			t.Fatalf("concurrent global key registration error=%v", err)
		}
	}
	if successes != 1 || keyConflicts != 1 {
		t.Fatalf("global key registration outcomes success=%d conflict=%d, want 1/1", successes, keyConflicts)
	}
	var boundDevice string
	if err := pool.QueryRow(ctx, `SELECT device_id FROM registered_device_attestations WHERE provider = $1 AND key_id = $2`, "integration-provider", "global-key-contested").Scan(&boundDevice); err != nil {
		t.Fatal(err)
	}
	if boundDevice != firstDevice.ID && boundDevice != secondDevice.ID {
		t.Fatalf("globally bound key points to unexpected device %q", boundDevice)
	}
	otherDevice := firstDevice.ID
	if boundDevice == otherDevice {
		otherDevice = secondDevice.ID
	}
	if err := repo.AuthorizeAttestation(ctx, "key-owner", otherDevice, "integration-provider", "global-key-contested"); !errors.Is(err, registry.ErrKeyBoundElsewhere) {
		t.Fatalf("authorize key on non-owning device error=%v, want ErrKeyBoundElsewhere", err)
	}

	rotationDevice, err := repo.EnsureDevice(ctx, "key-owner", "key-rotation-device", "integration-hardware", "nfc", now)
	if err != nil {
		t.Fatal(err)
	}
	registerIntegrationKey(t, ctx, repo, "key-owner", rotationDevice.ID, "rotation-initial-key", 1, now)
	rotationStart := make(chan struct{})
	rotationResults := make(chan error, 2)
	rotationKeys := []registry.KeyMetadata{testKey(t, "rotation-candidate-a", 2), testKey(t, "rotation-candidate-b", 3)}
	for _, key := range rotationKeys {
		key := key
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-rotationStart
			rotationResults <- repo.RegisterAttestation(ctx, "key-owner", rotationDevice.ID, key, now.Add(time.Duration(key.Counter)*time.Second))
		}()
	}
	close(rotationStart)
	wg.Wait()
	close(rotationResults)
	for err := range rotationResults {
		if err != nil {
			t.Fatalf("same-device concurrent key rotation: %v", err)
		}
	}
	var active, replaced int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE lifecycle_state = $1), COUNT(*) FILTER (WHERE lifecycle_state = $2) FROM registered_device_attestations WHERE device_id = $3 AND provider = $4`, registry.StateActive, registry.StateReplaced, rotationDevice.ID, "integration-provider").Scan(&active, &replaced); err != nil {
		t.Fatal(err)
	}
	if active != 1 || replaced != 2 {
		t.Fatalf("rotation lifecycle counts active=%d replaced=%d, want 1/2", active, replaced)
	}
	if err := repo.AuthorizeAttestation(ctx, "key-owner", rotationDevice.ID, "integration-provider", "rotation-initial-key"); !errors.Is(err, registry.ErrKeyReplaced) {
		t.Fatalf("authorize replaced key error=%v, want ErrKeyReplaced", err)
	}
	var activeKeyID string
	if err := pool.QueryRow(ctx, `SELECT key_id FROM registered_device_attestations WHERE device_id = $1 AND provider = $2 AND lifecycle_state = $3`, rotationDevice.ID, "integration-provider", registry.StateActive).Scan(&activeKeyID); err != nil {
		t.Fatal(err)
	}
	if err := repo.AuthorizeAttestation(ctx, "key-owner", rotationDevice.ID, "integration-provider", activeKeyID); err != nil {
		t.Fatalf("authorize current key %q: %v", activeKeyID, err)
	}
}

func registerIntegrationKey(t *testing.T, ctx context.Context, repo *postgres.DeviceRegistry, userID, deviceID, keyID string, counter uint64, now time.Time) {
	t.Helper()
	if err := repo.RegisterAttestation(ctx, userID, deviceID, testKey(t, keyID, counter), now); err != nil {
		t.Fatalf("register integration attestation key %q: %v", keyID, err)
	}
}

func testKey(t *testing.T, keyID string, counter uint64) registry.KeyMetadata {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate integration Ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal integration public key: %v", err)
	}
	return registry.KeyMetadata{Provider: "integration-provider", KeyID: keyID, PublicKeyDER: der, BundleVersion: "integration", Environment: "test", Counter: counter}
}
