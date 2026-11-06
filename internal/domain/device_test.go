package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testDevice(t *testing.T) Device {
	t.Helper()
	device, err := NewDevice("device-1", "owner-1", strings.Repeat("a", 64), "wearable-v1", "ble", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func TestNewDeviceStartsDiscoveredWithoutTrust(t *testing.T) {
	device := testDevice(t)
	if device.State != DeviceStateDiscovered || len(device.Attestations) != 0 {
		t.Fatalf("unexpected initial device: %+v", device)
	}
	if err := device.Validate(); err != nil {
		t.Fatalf("new device should validate: %v", err)
	}
}

func TestDeviceLifecycleRequiresAttestationBeforeActivation(t *testing.T) {
	device := testDevice(t)
	at := time.Unix(101, 0).UTC()
	if err := device.Transition(DeviceStatePendingAttestation, at); err != nil {
		t.Fatal(err)
	}
	if err := device.Transition(DeviceStateActive, at.Add(time.Second)); !errors.Is(err, ErrNoVerifiedAttestation) {
		t.Fatalf("expected missing-attestation error, got %v", err)
	}
	if device.State != DeviceStatePendingAttestation {
		t.Fatalf("failed transition changed state to %s", device.State)
	}
	if err := device.RecordAttestation("apple-app-attest", "key-1", "apple-verified", 0, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := device.Transition(DeviceStateActive, at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if device.State != DeviceStateActive {
		t.Fatalf("expected active state, got %s", device.State)
	}
}

func TestDeviceLifecycleRejectsIllegalEdgesAndRetiresTerminally(t *testing.T) {
	device := testDevice(t)
	at := time.Unix(101, 0).UTC()
	if err := device.Transition(DeviceStateActive, at); !errors.Is(err, ErrInvalidDeviceTransition) {
		t.Fatalf("expected illegal edge error, got %v", err)
	}
	if err := device.Transition(DeviceStatePendingAttestation, at); err != nil {
		t.Fatal(err)
	}
	if err := device.RecordAttestation("aws-kms", "key-1", "kms-verified", 1, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := device.Transition(DeviceStateActive, at.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := device.Transition(DeviceStateRetired, at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := device.Transition(DeviceStateActive, at.Add(4*time.Second)); !errors.Is(err, ErrInvalidDeviceTransition) {
		t.Fatalf("retired device should be terminal, got %v", err)
	}
	if device.RetiredAt == nil || !device.RetiredAt.Equal(at.Add(3*time.Second)) {
		t.Fatalf("retirement timestamp not recorded: %+v", device.RetiredAt)
	}
}

func TestRecordAttestationEnforcesMonotonicCounter(t *testing.T) {
	device := testDevice(t)
	at := time.Unix(101, 0).UTC()
	if err := device.RecordAttestation("android-play-integrity", "package-key", "play-recognized", 4, at); err != nil {
		t.Fatal(err)
	}
	if err := device.RecordAttestation("android-play-integrity", "package-key", "play-recognized", 4, at.Add(time.Second)); !errors.Is(err, ErrAttestationCounterRollback) {
		t.Fatalf("expected equal-counter rejection, got %v", err)
	}
	if err := device.RecordAttestation("android-play-integrity", "package-key", "play-recognized", 3, at.Add(2*time.Second)); !errors.Is(err, ErrAttestationCounterRollback) {
		t.Fatalf("expected rollback rejection, got %v", err)
	}
	if err := device.RecordAttestation("android-play-integrity", "package-key", "play-recognized", 5, at.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := device.Attestations[0].Counter; got != 5 {
		t.Fatalf("expected counter 5, got %d", got)
	}
}

func TestRevokedAttestationKeyCannotBeUpdated(t *testing.T) {
	device := testDevice(t)
	at := time.Unix(101, 0).UTC()
	if err := device.RecordAttestation("apple-app-attest", "key-1", "apple-verified", 1, at); err != nil {
		t.Fatal(err)
	}
	if err := device.RevokeAttestation("apple-app-attest", "key-1", "compromised", at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := device.RecordAttestation("apple-app-attest", "key-1", "apple-verified", 2, at.Add(2*time.Second)); !errors.Is(err, ErrAttestationKeyRevoked) {
		t.Fatalf("expected revoked-key rejection, got %v", err)
	}
	if device.Attestations[0].RevokedAt == nil || device.Attestations[0].RevocationReason != "compromised" {
		t.Fatalf("revocation metadata missing: %+v", device.Attestations[0])
	}
}

func TestDeviceValidationRejectsSensitiveOrMalformedIdentity(t *testing.T) {
	for _, identityHash := range []string{"raw-device-id", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := NewDevice("device-1", "owner-1", identityHash, "wearable-v1", "ble", time.Unix(100, 0).UTC()); !errors.Is(err, ErrInvalidDevice) {
			t.Fatalf("identity %q should be rejected, got %v", identityHash, err)
		}
	}
	if _, err := NewDevice("device-1", "owner-1", strings.Repeat("a", 64), "wearable-v1", "wifi", time.Unix(100, 0).UTC()); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("unsupported transport should be rejected, got %v", err)
	}
}
