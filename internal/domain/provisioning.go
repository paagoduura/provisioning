package domain

import (
	"errors"
	"fmt"
	"time"
)

type ProvisioningState string

const (
	StateCreated              ProvisioningState = "CREATED"
	StateDeviceDiscovered     ProvisioningState = "DEVICE_DISCOVERED"
	StateDeviceAttested       ProvisioningState = "DEVICE_ATTESTED"
	StateSessionAuthenticated ProvisioningState = "SESSION_AUTHENTICATED"
	StateTokenRequested       ProvisioningState = "TOKEN_REQUESTED"
	StateTokenReceived        ProvisioningState = "TOKEN_RECEIVED"
	StatePayloadWrapped       ProvisioningState = "PAYLOAD_WRAPPED"
	StateTransferStarted      ProvisioningState = "APDU_TRANSFER_STARTED"
	StateTransferred          ProvisioningState = "APDU_TRANSFERRED"
	StateDeviceVerified       ProvisioningState = "DEVICE_VERIFIED"
	StateCompleted            ProvisioningState = "COMPLETED"
	StateFailed               ProvisioningState = "FAILED"
)

var ErrInvalidTransition = errors.New("invalid provisioning state transition")
var ErrSessionNotFound = errors.New("session not found")

var transitions = map[ProvisioningState]map[ProvisioningState]bool{
	StateCreated:              {StateDeviceDiscovered: true, StateFailed: true},
	StateDeviceDiscovered:     {StateDeviceAttested: true, StateFailed: true},
	StateDeviceAttested:       {StateSessionAuthenticated: true, StateFailed: true},
	StateSessionAuthenticated: {StateTokenRequested: true, StateFailed: true},
	StateTokenRequested:       {StateTokenReceived: true, StateFailed: true},
	StateTokenReceived:        {StatePayloadWrapped: true, StateFailed: true},
	StatePayloadWrapped:       {StateTransferStarted: true, StateFailed: true},
	StateTransferStarted:      {StateTransferred: true, StateFailed: true},
	StateTransferred:          {StateDeviceVerified: true, StateFailed: true},
	StateDeviceVerified:       {StateCompleted: true, StateFailed: true},
}

type ProvisioningSession struct {
	ID             string            `json:"id"`
	IdempotencyKey string            `json:"-"`
	UserID         string            `json:"user_id"`
	DeviceUID      string            `json:"device_uid"`
	DeviceModel    string            `json:"device_model"`
	Transport      string            `json:"transport"`
	State          ProvisioningState `json:"state"`
	Correlation    string            `json:"correlation_id"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	FailureCode    string            `json:"failure_code,omitempty"`
}

func (s *ProvisioningSession) Transition(next ProvisioningState) error {
	if s.State == next {
		return nil
	}
	if !transitions[s.State][next] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.State, next)
	}
	s.State = next
	return nil
}

func (s ProvisioningSession) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }
