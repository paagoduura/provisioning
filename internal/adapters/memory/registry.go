package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/paagoduura/provisioning/internal/registry"
)

type DeviceRegistry struct {
	mu         sync.RWMutex
	devices    map[string]registry.Device
	byOwnerUID map[string]string
	keys       map[string]registry.AttestationKey
}

func NewDeviceRegistry() *DeviceRegistry {
	return &DeviceRegistry{
		devices:    make(map[string]registry.Device),
		byOwnerUID: make(map[string]string),
		keys:       make(map[string]registry.AttestationKey),
	}
}

func (r *DeviceRegistry) EnsureDevice(_ context.Context, userID, deviceUID, model, transport string, now time.Time) (registry.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ownerKey := userID + "\x00" + deviceUID
	if id, ok := r.byOwnerUID[ownerKey]; ok {
		return r.devices[id], nil
	}
	for _, existing := range r.devices {
		if existing.DeviceUID == deviceUID && existing.UserID != userID {
			return registry.Device{}, registry.ErrDeviceAlreadyOwned
		}
	}
	id, err := randomDeviceID()
	if err != nil {
		return registry.Device{}, err
	}
	device := registry.Device{ID: id, UserID: userID, DeviceUID: deviceUID, DeviceModel: model, Transport: transport, State: registry.StatePending, CreatedAt: now, UpdatedAt: now}
	r.devices[id] = device
	r.byOwnerUID[ownerKey] = id
	return device, nil
}

func (r *DeviceRegistry) GetDevice(_ context.Context, userID, deviceID string) (registry.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	device, ok := r.devices[deviceID]
	if !ok {
		return registry.Device{}, registry.ErrDeviceNotFound
	}
	if device.UserID != userID {
		return registry.Device{}, registry.ErrDeviceNotFound
	}
	return device, nil
}

func (r *DeviceRegistry) ListDevices(_ context.Context, userID string) ([]registry.Device, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]registry.Device, 0)
	for _, device := range r.devices {
		if device.UserID == userID {
			device.DeviceUID = ""
			result = append(result, device)
		}
	}
	return result, nil
}

func (r *DeviceRegistry) AuthorizeAttestation(_ context.Context, userID, deviceID, provider, keyID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	device, ok := r.devices[deviceID]
	if !ok || device.UserID != userID {
		return registry.ErrDeviceNotFound
	}
	if !registry.IsUsable(device.State) {
		return registry.ErrDeviceUnavailable
	}
	if key, exists := r.keys[provider+"\x00"+keyID]; exists {
		if key.DeviceID != deviceID {
			return registry.ErrKeyBoundElsewhere
		}
		switch key.State {
		case registry.StateRevoked:
			return registry.ErrKeyRevoked
		case registry.StateReplaced:
			return registry.ErrKeyReplaced
		}
	}
	return nil
}

func (r *DeviceRegistry) RegisterAttestation(_ context.Context, userID, deviceID string, metadata registry.KeyMetadata, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	device, ok := r.devices[deviceID]
	if !ok || device.UserID != userID {
		return registry.ErrDeviceNotFound
	}
	if !registry.IsUsable(device.State) {
		return registry.ErrDeviceUnavailable
	}
	keyName := metadata.Provider + "\x00" + metadata.KeyID
	if existing, exists := r.keys[keyName]; exists {
		if existing.DeviceID != deviceID {
			return registry.ErrKeyBoundElsewhere
		}
		if existing.State == registry.StateRevoked || existing.State == registry.StateReplaced {
			return registry.ErrKeyRevoked
		}
		if metadata.Counter <= existing.Counter {
			return registry.ErrCounterRollback
		}
		existing.PublicKeyDER = append([]byte(nil), metadata.PublicKeyDER...)
		existing.BundleVersion = metadata.BundleVersion
		existing.Environment = metadata.Environment
		existing.Counter = metadata.Counter
		existing.LastSeenAt = now
		r.keys[keyName] = existing
		device.State = registry.StateActive
		device.UpdatedAt = now
		r.devices[deviceID] = device
		return nil
	}
	for name, existing := range r.keys {
		if existing.DeviceID == deviceID && existing.Provider == metadata.Provider && existing.State == registry.StateActive {
			existing.State = registry.StateReplaced
			existing.ReplacedByKey = metadata.KeyID
			r.keys[name] = existing
		}
	}
	r.keys[keyName] = registry.AttestationKey{DeviceID: deviceID, Provider: metadata.Provider, KeyID: metadata.KeyID, PublicKeyDER: append([]byte(nil), metadata.PublicKeyDER...), BundleVersion: metadata.BundleVersion, Environment: metadata.Environment, Counter: metadata.Counter, State: registry.StateActive, RegisteredAt: now, LastSeenAt: now}
	device.State = registry.StateActive
	device.UpdatedAt = now
	r.devices[deviceID] = device
	return nil
}

func (r *DeviceRegistry) RevokeDevice(_ context.Context, userID, deviceID, reason string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	device, ok := r.devices[deviceID]
	if !ok || device.UserID != userID {
		return registry.ErrDeviceNotFound
	}
	if device.State == registry.StateRevoked || device.State == registry.StateRetired {
		return nil
	}
	device.State = registry.StateRevoked
	device.RevokedAt = &now
	device.UpdatedAt = now
	r.devices[deviceID] = device
	for name, key := range r.keys {
		if key.DeviceID == deviceID && key.State == registry.StateActive {
			key.State = registry.StateRevoked
			key.RevokedAt = &now
			r.keys[name] = key
		}
	}
	_ = reason
	return nil
}

func (r *DeviceRegistry) SetLifecycle(_ context.Context, userID, deviceID string, next registry.LifecycleState, reason string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	device, ok := r.devices[deviceID]
	if !ok || device.UserID != userID {
		return registry.ErrDeviceNotFound
	}
	valid := (device.State == registry.StateActive && (next == registry.StateSuspended || next == registry.StateRetired)) || (device.State == registry.StateSuspended && next == registry.StateActive)
	if !valid {
		return registry.ErrInvalidLifecycle
	}
	device.State = next
	device.UpdatedAt = now
	r.devices[deviceID] = device
	if next == registry.StateRetired {
		for name, key := range r.keys {
			if key.DeviceID == deviceID && key.State == registry.StateActive {
				key.State = registry.StateRevoked
				key.RevokedAt = &now
				r.keys[name] = key
			}
		}
	}
	_ = reason
	return nil
}

func (r *DeviceRegistry) ReplaceDevice(_ context.Context, userID, deviceID, newUID, model, transport string, now time.Time) (registry.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.devices[deviceID]
	if !ok || old.UserID != userID {
		return registry.Device{}, registry.ErrDeviceNotFound
	}
	if !registry.IsUsable(old.State) {
		return registry.Device{}, registry.ErrDeviceUnavailable
	}
	if id, exists := r.byOwnerUID[userID+"\x00"+newUID]; exists && id != deviceID {
		return registry.Device{}, registry.ErrDeviceAlreadyOwned
	}
	for _, existing := range r.devices {
		if existing.DeviceUID == newUID && existing.UserID != userID {
			return registry.Device{}, registry.ErrDeviceAlreadyOwned
		}
	}
	newID, err := randomDeviceID()
	if err != nil {
		return registry.Device{}, err
	}
	replacement := registry.Device{ID: newID, UserID: userID, DeviceUID: newUID, DeviceModel: model, Transport: transport, State: registry.StatePending, CreatedAt: now, UpdatedAt: now}
	old.State = registry.StateReplaced
	old.ReplacedByID = newID
	old.UpdatedAt = now
	r.devices[deviceID] = old
	r.devices[newID] = replacement
	delete(r.byOwnerUID, userID+"\x00"+old.DeviceUID)
	r.byOwnerUID[userID+"\x00"+newUID] = newID
	for name, key := range r.keys {
		if key.DeviceID == deviceID && key.State == registry.StateActive {
			key.State = registry.StateReplaced
			r.keys[name] = key
		}
	}
	return replacement, nil
}

func randomDeviceID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	return "dev_" + hex.EncodeToString(buf), nil
}
