package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
)

type deviceRepositoryForTest struct {
	devices map[string]domain.Device
}

func (r *deviceRepositoryForTest) Create(_ context.Context, device domain.Device) error {
	if _, exists := r.devices[device.ID]; exists {
		return errors.New("device already exists")
	}
	r.devices[device.ID] = device
	return nil
}

func (r *deviceRepositoryForTest) Get(_ context.Context, id string) (domain.Device, error) {
	device, ok := r.devices[id]
	if !ok {
		return domain.Device{}, domain.ErrDeviceNotFound
	}
	return device, nil
}

func (r *deviceRepositoryForTest) Save(_ context.Context, device domain.Device) error {
	if _, ok := r.devices[device.ID]; !ok {
		return domain.ErrDeviceNotFound
	}
	r.devices[device.ID] = device
	return nil
}

func TestDeviceServiceRegistersAndActivatesVerifiedDevice(t *testing.T) {
	repo := &deviceRepositoryForTest{devices: make(map[string]domain.Device)}
	service := NewDeviceService(repo)
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	session := domain.ProvisioningSession{
		ID:          "ps_1",
		UserID:      "owner-1",
		DeviceUID:   "hardware-identity-1",
		DeviceModel: "wearable-v1",
		Transport:   "ble",
		State:       domain.StateDeviceDiscovered,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}
	result := attestation.VerifiedResult{Provider: "aws-kms", KeyID: "key-1", TrustLevel: "aws-kms-hsm-verified", Counter: 1}

	device, err := service.RecordVerifiedAttestation(context.Background(), session, result)
	if err != nil {
		t.Fatal(err)
	}
	if device.State != domain.DeviceStateActive || len(device.Attestations) != 1 {
		t.Fatalf("unexpected registered device: %+v", device)
	}
	if device.DeviceIdentityHash != hashDeviceIdentity(session.DeviceUID) {
		t.Fatal("device identity was not stored as the expected hash")
	}
	if _, ok := repo.devices[device.ID]; !ok {
		t.Fatal("device was not durably handed to the repository")
	}
}

func TestDeviceServiceUsesPersistedSessionIdentityHash(t *testing.T) {
	repo := &deviceRepositoryForTest{devices: make(map[string]domain.Device)}
	service := NewDeviceService(repo)
	now := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	session := domain.ProvisioningSession{
		ID:                 "ps_2",
		UserID:             "owner-2",
		DeviceIdentityHash: hashDeviceIdentity("original-identity"),
		DeviceModel:        "wearable-v2",
		Transport:          "nfc",
		State:              domain.StateDeviceDiscovered,
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Hour),
	}

	device, err := service.RegisterFromSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceIdentityHash != session.DeviceIdentityHash {
		t.Fatalf("got identity hash %q, want persisted hash %q", device.DeviceIdentityHash, session.DeviceIdentityHash)
	}
}
