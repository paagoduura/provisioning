package domain

import (
	"crypto/subtle"
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
	StateTokenRequesting      ProvisioningState = "TOKEN_REQUESTING"
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
var ErrSessionExpired = errors.New("provisioning session has expired")
var ErrConcurrentUpdate = errors.New("provisioning session was concurrently updated")
var ErrWebhookEventConflict = errors.New("webhook event identifier was reused with different content")
var ErrTokenRequestInProgress = errors.New("token request is already in progress")
var ErrTokenRequestOutcomeUnknown = errors.New("token request outcome is unknown and requires reconciliation")
var ErrTokenRequestConflict = errors.New("token request provider reference conflicts with the recorded operation")
var ErrIdempotencyConflict = errors.New("idempotency key conflicts with an existing request")

// IdempotencyFingerprintsMatch compares only valid SHA-256 fingerprints.
// Two absent fingerprints are accepted for direct legacy repository fixtures;
// a legacy row can never match a new request carrying a fingerprint.
func IdempotencyFingerprintsMatch(existing, incoming []byte) bool {
	if len(existing) == 0 && len(incoming) == 0 {
		return true
	}
	if len(existing) != 32 || len(incoming) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(existing, incoming) == 1
}

// TokenWebhookEvent is the verified, provider-originated event used to advance
// a session. Repositories persist its identity atomically with the transition.
type TokenWebhookEvent struct {
	EventID        string
	SessionID      string
	TokenReference string
}

type TokenRequestStatus string

const (
	TokenRequestPending   TokenRequestStatus = "PENDING"
	TokenRequestUnknown   TokenRequestStatus = "UNKNOWN"
	TokenRequestSucceeded TokenRequestStatus = "SUCCEEDED"
)

// TokenRequestOperation is the durable record for one provider side effect.
// IdempotencyKey is stable for the life of the provisioning session.
type TokenRequestOperation struct {
	SessionID         string
	IdempotencyKey    string
	Status            TokenRequestStatus
	ProviderReference string
	LastErrorCode     string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type TokenRequestClaim struct {
	Session   ProvisioningSession
	Operation TokenRequestOperation
	Claimed   bool
}

func TokenRequestIdempotencyKey(sessionID string) string {
	return "provisioning-token-v1:" + sessionID
}

var transitions = map[ProvisioningState]map[ProvisioningState]bool{
	StateCreated:              {StateDeviceDiscovered: true, StateFailed: true},
	StateDeviceDiscovered:     {StateDeviceAttested: true, StateFailed: true},
	StateDeviceAttested:       {StateSessionAuthenticated: true, StateFailed: true},
	StateSessionAuthenticated: {StateTokenRequesting: true, StateFailed: true},
	StateTokenRequesting:      {StateTokenRequested: true, StateTokenReceived: true},
	StateTokenRequested:       {StateTokenReceived: true, StateFailed: true},
	StateTokenReceived:        {StatePayloadWrapped: true, StateFailed: true},
	StatePayloadWrapped:       {StateTransferStarted: true, StateFailed: true},
	StateTransferStarted:      {StateTransferred: true, StateFailed: true},
	StateTransferred:          {StateDeviceVerified: true, StateFailed: true},
	StateDeviceVerified:       {StateCompleted: true, StateFailed: true},
}

type ProvisioningSession struct {
	ID                 string            `json:"id"`
	IdempotencyKey     string            `json:"-"`
	RequestFingerprint []byte            `json:"-"`
	UserID             string            `json:"user_id"`
	DeviceID           string            `json:"device_id,omitempty"`
	DeviceUID          string            `json:"device_uid"`
	DeviceModel        string            `json:"device_model"`
	Transport          string            `json:"transport"`
	State              ProvisioningState `json:"state"`
	Version            int64             `json:"version"`
	Correlation        string            `json:"correlation_id"`
	CreatedAt          time.Time         `json:"created_at"`
	ExpiresAt          time.Time         `json:"expires_at"`
	FailureCode        string            `json:"failure_code,omitempty"`
	TokenReference     string            `json:"-"`
	WrappedPayload     string            `json:"-"`
	APDUReceipt        string            `json:"-"`
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
