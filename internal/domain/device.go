package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DeviceLifecycleState is the authoritative lifecycle state of a registered device.
type DeviceLifecycleState string

const (
	DeviceStateDiscovered         DeviceLifecycleState = "DISCOVERED"
	DeviceStatePendingAttestation DeviceLifecycleState = "PENDING_ATTESTATION"
	DeviceStateActive             DeviceLifecycleState = "ACTIVE"
	DeviceStateSuspended          DeviceLifecycleState = "SUSPENDED"
	DeviceStateRevoked            DeviceLifecycleState = "REVOKED"
	DeviceStateRetired            DeviceLifecycleState = "RETIRED"
)

var (
	ErrInvalidDevice              = errors.New("invalid device")
	ErrInvalidDeviceTransition    = errors.New("invalid device lifecycle transition")
	ErrNoVerifiedAttestation      = errors.New("device has no verified attestation")
	ErrAttestationKeyRevoked      = errors.New("device attestation key is revoked")
	ErrAttestationCounterRollback = errors.New("device attestation counter did not increase")
)

// Device is the durable device-registry aggregate. DeviceIdentityHash is a
// lowercase SHA-256 hex digest; the raw device identifier is deliberately not
// part of this aggregate and must not be persisted by registry adapters.
type Device struct {
	ID                 string               `json:"id"`
	OwnerID            string               `json:"owner_id"`
	DeviceIdentityHash string               `json:"device_identity_hash"`
	Model              string               `json:"model"`
	Transport          string               `json:"transport"`
	State              DeviceLifecycleState `json:"state"`
	Attestations       []DeviceAttestation  `json:"attestations,omitempty"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
	SuspendedAt        *time.Time           `json:"suspended_at,omitempty"`
	RevokedAt          *time.Time           `json:"revoked_at,omitempty"`
	RetiredAt          *time.Time           `json:"retired_at,omitempty"`
}

// DeviceAttestation records the provider identity bound to a device and the
// latest accepted monotonic counter for that provider key.
type DeviceAttestation struct {
	Provider         string     `json:"provider"`
	KeyID            string     `json:"key_id"`
	TrustLevel       string     `json:"trust_level"`
	Counter          uint64     `json:"counter"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

// NewDevice creates a device in the discovered state. Attestation is
// intentionally a separate transition so registration cannot imply trust.
func NewDevice(id, ownerID, identityHash, model, transport string, now time.Time) (Device, error) {
	device := Device{
		ID:                 strings.TrimSpace(id),
		OwnerID:            strings.TrimSpace(ownerID),
		DeviceIdentityHash: strings.TrimSpace(identityHash),
		Model:              strings.TrimSpace(model),
		Transport:          strings.ToLower(strings.TrimSpace(transport)),
		State:              DeviceStateDiscovered,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := device.Validate(); err != nil {
		return Device{}, err
	}
	return device, nil
}

// Validate enforces aggregate invariants independently of persistence.
func (d Device) Validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.OwnerID) == "" || strings.TrimSpace(d.Model) == "" {
		return fmt.Errorf("%w: id, owner_id and model are required", ErrInvalidDevice)
	}
	if len(d.DeviceIdentityHash) != 64 {
		return fmt.Errorf("%w: device_identity_hash must be a SHA-256 hex digest", ErrInvalidDevice)
	}
	if _, err := hex.DecodeString(d.DeviceIdentityHash); err != nil || d.DeviceIdentityHash != strings.ToLower(d.DeviceIdentityHash) {
		return fmt.Errorf("%w: device_identity_hash must be lowercase hexadecimal", ErrInvalidDevice)
	}
	if d.Transport != "nfc" && d.Transport != "ble" {
		return fmt.Errorf("%w: transport must be nfc or ble", ErrInvalidDevice)
	}
	if !validDeviceState(d.State) {
		return fmt.Errorf("%w: unknown lifecycle state %q", ErrInvalidDevice, d.State)
	}
	if d.CreatedAt.IsZero() || d.UpdatedAt.IsZero() || d.UpdatedAt.Before(d.CreatedAt) {
		return fmt.Errorf("%w: invalid creation or update timestamps", ErrInvalidDevice)
	}
	if d.State == DeviceStateActive && len(d.Attestations) == 0 {
		return fmt.Errorf("%w: active device requires an attestation", ErrInvalidDevice)
	}
	seen := make(map[string]struct{}, len(d.Attestations))
	for _, attestation := range d.Attestations {
		if err := validateAttestation(attestation); err != nil {
			return err
		}
		key := attestation.Provider + "\x00" + attestation.KeyID
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate attestation provider/key", ErrInvalidDevice)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Transition moves the aggregate through an explicitly allowed lifecycle edge.
func (d *Device) Transition(next DeviceLifecycleState, at time.Time) error {
	if d == nil {
		return fmt.Errorf("%w: nil device", ErrInvalidDevice)
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if at.IsZero() || at.Before(d.UpdatedAt) {
		return fmt.Errorf("%w: transition timestamp must not move backwards", ErrInvalidDevice)
	}
	if !allowedDeviceTransition(d.State, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidDeviceTransition, d.State, next)
	}
	if next == DeviceStateActive && len(d.Attestations) == 0 {
		return ErrNoVerifiedAttestation
	}
	d.State = next
	d.UpdatedAt = at
	switch next {
	case DeviceStateSuspended:
		d.SuspendedAt = timePtr(at)
	case DeviceStateRevoked:
		d.RevokedAt = timePtr(at)
	case DeviceStateRetired:
		d.RetiredAt = timePtr(at)
	}
	return nil
}

// RecordAttestation adds or updates a provider key after successful provider
// verification. Existing counters must strictly increase to prevent replay.
func (d *Device) RecordAttestation(provider, keyID, trustLevel string, counter uint64, at time.Time) error {
	if d == nil {
		return fmt.Errorf("%w: nil device", ErrInvalidDevice)
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if d.State == DeviceStateRevoked || d.State == DeviceStateRetired {
		return fmt.Errorf("%w: device is %s", ErrInvalidDeviceTransition, d.State)
	}
	provider, keyID, trustLevel = strings.TrimSpace(provider), strings.TrimSpace(keyID), strings.TrimSpace(trustLevel)
	if provider == "" || keyID == "" || trustLevel == "" || at.IsZero() || at.Before(d.UpdatedAt) {
		return fmt.Errorf("%w: invalid attestation", ErrInvalidDevice)
	}
	for i := range d.Attestations {
		attestation := &d.Attestations[i]
		if attestation.Provider != provider || attestation.KeyID != keyID {
			continue
		}
		if attestation.RevokedAt != nil {
			return ErrAttestationKeyRevoked
		}
		if counter <= attestation.Counter {
			return ErrAttestationCounterRollback
		}
		attestation.Counter = counter
		attestation.TrustLevel = trustLevel
		attestation.LastSeenAt = at
		d.UpdatedAt = at
		return nil
	}
	d.Attestations = append(d.Attestations, DeviceAttestation{Provider: provider, KeyID: keyID, TrustLevel: trustLevel, Counter: counter, FirstSeenAt: at, LastSeenAt: at})
	d.UpdatedAt = at
	return nil
}

// RevokeAttestation prevents a provider key from being used again while
// preserving the device aggregate and an auditable reason.
func (d *Device) RevokeAttestation(provider, keyID, reason string, at time.Time) error {
	if d == nil {
		return fmt.Errorf("%w: nil device", ErrInvalidDevice)
	}
	for i := range d.Attestations {
		attestation := &d.Attestations[i]
		if attestation.Provider == provider && attestation.KeyID == keyID {
			if at.IsZero() || at.Before(d.UpdatedAt) || strings.TrimSpace(reason) == "" {
				return fmt.Errorf("%w: invalid attestation revocation", ErrInvalidDevice)
			}
			attestation.RevokedAt = timePtr(at)
			attestation.RevocationReason = strings.TrimSpace(reason)
			d.UpdatedAt = at
			return nil
		}
	}
	return fmt.Errorf("%w: attestation provider/key not found", ErrInvalidDevice)
}

func validDeviceState(state DeviceLifecycleState) bool {
	switch state {
	case DeviceStateDiscovered, DeviceStatePendingAttestation, DeviceStateActive, DeviceStateSuspended, DeviceStateRevoked, DeviceStateRetired:
		return true
	default:
		return false
	}
}

func allowedDeviceTransition(from, to DeviceLifecycleState) bool {
	switch from {
	case DeviceStateDiscovered:
		return to == DeviceStatePendingAttestation || to == DeviceStateSuspended || to == DeviceStateRetired
	case DeviceStatePendingAttestation:
		return to == DeviceStateActive || to == DeviceStateSuspended || to == DeviceStateRevoked || to == DeviceStateRetired
	case DeviceStateActive:
		return to == DeviceStateSuspended || to == DeviceStateRevoked || to == DeviceStateRetired
	case DeviceStateSuspended:
		return to == DeviceStateActive || to == DeviceStateRevoked || to == DeviceStateRetired
	case DeviceStateRevoked:
		return to == DeviceStateRetired
	case DeviceStateRetired:
		return false
	default:
		return false
	}
}

func validateAttestation(attestation DeviceAttestation) error {
	if strings.TrimSpace(attestation.Provider) == "" || strings.TrimSpace(attestation.KeyID) == "" || strings.TrimSpace(attestation.TrustLevel) == "" {
		return fmt.Errorf("%w: attestation provider, key_id and trust_level are required", ErrInvalidDevice)
	}
	if attestation.FirstSeenAt.IsZero() || attestation.LastSeenAt.IsZero() || attestation.LastSeenAt.Before(attestation.FirstSeenAt) {
		return fmt.Errorf("%w: invalid attestation timestamps", ErrInvalidDevice)
	}
	if attestation.RevokedAt != nil && attestation.RevokedAt.Before(attestation.LastSeenAt) {
		return fmt.Errorf("%w: attestation revoked before last use", ErrInvalidDevice)
	}
	return nil
}

func timePtr(at time.Time) *time.Time {
	copy := at
	return &copy
}
