package registry

import (
	"context"
	"errors"
	"time"
)

type LifecycleState string

const (
	StatePending   LifecycleState = "PENDING"
	StateActive    LifecycleState = "ACTIVE"
	StateSuspended LifecycleState = "SUSPENDED"
	StateRevoked   LifecycleState = "REVOKED"
	StateReplaced  LifecycleState = "REPLACED"
	StateRetired   LifecycleState = "RETIRED"
)

var (
	ErrDeviceNotFound      = errors.New("registered device not found")
	ErrDeviceAlreadyOwned  = errors.New("device is already owned by another user")
	ErrDeviceNotOwned      = errors.New("device is not owned by the authenticated user")
	ErrDeviceUnavailable   = errors.New("registered device is not available")
	ErrKeyNotRegistered    = errors.New("attestation key is not registered")
	ErrKeyBoundElsewhere   = errors.New("attestation key is bound to another device")
	ErrKeyRevoked          = errors.New("attestation key is revoked")
	ErrKeyReplaced         = errors.New("attestation key was replaced")
	ErrInvalidLifecycle    = errors.New("invalid device lifecycle transition")
	ErrReplacementRequired = errors.New("replacement device is required")
	ErrCounterRollback     = errors.New("registered attestation counter did not increase")
)

type Device struct {
	ID           string         `json:"id"`
	UserID       string         `json:"-"`
	DeviceUID    string         `json:"-"`
	DeviceModel  string         `json:"device_model"`
	Transport    string         `json:"transport"`
	State        LifecycleState `json:"state"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	RevokedAt    *time.Time     `json:"revoked_at,omitempty"`
	ReplacedByID string         `json:"replaced_by_id,omitempty"`
}

type AttestationKey struct {
	DeviceID      string
	Provider      string
	KeyID         string
	PublicKeyDER  []byte
	BundleVersion string
	Environment   string
	Counter       uint64
	State         LifecycleState
	RegisteredAt  time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	ReplacedByKey string
}

type KeyMetadata struct {
	Provider      string
	KeyID         string
	PublicKeyDER  []byte
	BundleVersion string
	Environment   string
	Counter       uint64
}

type Repository interface {
	EnsureDevice(context.Context, string, string, string, string, time.Time) (Device, error)
	GetDevice(context.Context, string, string) (Device, error)
	ListDevices(context.Context, string) ([]Device, error)
	AuthorizeAttestation(context.Context, string, string, string, string) error
	RegisterAttestation(context.Context, string, string, KeyMetadata, time.Time) error
	RevokeDevice(context.Context, string, string, string, time.Time) error
	SetLifecycle(context.Context, string, string, LifecycleState, string, time.Time) error
	ReplaceDevice(context.Context, string, string, string, string, string, time.Time) (Device, error)
}

func IsUsable(state LifecycleState) bool {
	return state == StatePending || state == StateActive
}
