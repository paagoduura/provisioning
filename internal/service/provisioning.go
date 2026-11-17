package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/audit"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/internal/registry"
)

type Repository interface {
	Create(context.Context, domain.ProvisioningSession) (domain.ProvisioningSession, bool, error)
	Get(context.Context, string) (domain.ProvisioningSession, error)
	Save(context.Context, domain.ProvisioningSession) (domain.ProvisioningSession, error)
	ReceiveTokenWebhook(context.Context, domain.TokenWebhookEvent, time.Time) (domain.ProvisioningSession, bool, error)
	ClaimTokenRequest(context.Context, string, time.Time) (domain.TokenRequestClaim, error)
	MarkTokenRequestUnknown(context.Context, string, string, time.Time) (domain.TokenRequestClaim, error)
	CompleteTokenRequest(context.Context, string, string, time.Time) (domain.ProvisioningSession, bool, error)
}
type CryptoPort interface {
	CreateChallenge(context.Context, string, string) (string, error)
	VerifyDeviceResponse(context.Context, string, string, string) error
}
type SessionAuthenticator interface {
	AuthenticateSession(context.Context, domain.ProvisioningSession, string) error
}
type DeviceVerifier interface {
	VerifyDevice(context.Context, domain.ProvisioningSession, string) error
}
type TokenPort interface {
	RequestToken(context.Context, string, string) (string, error)
}
type PayloadWrapper interface {
	WrapPayload(context.Context, domain.ProvisioningSession, string) (string, error)
}
type APDUTransport interface {
	Transfer(context.Context, domain.ProvisioningSession, string) error
}
type AuditPort interface {
	Record(context.Context, audit.Event) error
}
type TokenWebhook struct{ SessionID, TokenReference, EventID string }
type TokenWebhookVerifier interface {
	VerifyTokenWebhook(context.Context, []byte, map[string]string) (TokenWebhook, error)
}
type CreateInput struct{ UserID, DeviceUID, DeviceModel, Transport string }
type Service struct {
	repo           Repository
	crypto         CryptoPort
	tokens         TokenPort
	audit          AuditPort
	devices        registry.Repository
	authenticator  SessionAuthenticator
	deviceVerifier DeviceVerifier
	wrapper        PayloadWrapper
	transfer       APDUTransport
	now            func() time.Time
}

var (
	ErrStageUnavailable  = errors.New("provisioning stage is unavailable")
	ErrInvalidStageInput = errors.New("invalid provisioning stage input")
	ErrTokenNotReceived  = errors.New("token has not been received")
)

func New(repo Repository, crypto CryptoPort, tokens TokenPort, auditSink AuditPort) *Service {
	return &Service{repo: repo, crypto: crypto, tokens: tokens, audit: auditSink, now: time.Now}
}
func (s *Service) SetDeviceRegistry(devices registry.Repository)  { s.devices = devices }
func (s *Service) SetSessionAuthenticator(v SessionAuthenticator) { s.authenticator = v }
func (s *Service) SetDeviceVerifier(v DeviceVerifier)             { s.deviceVerifier = v }
func (s *Service) SetPayloadWrapper(v PayloadWrapper)             { s.wrapper = v }
func (s *Service) SetAPDUTransport(v APDUTransport)               { s.transfer = v }
func (s *Service) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.repo.Get(ctx, id)
}
func (s *Service) Create(ctx context.Context, input CreateInput, idempotencyKey string) (domain.ProvisioningSession, bool, error) {
	if strings.TrimSpace(idempotencyKey) == "" || len(idempotencyKey) > 256 || strings.ContainsAny(idempotencyKey, "\r\n") {
		return domain.ProvisioningSession{}, false, errors.New("idempotency key is required")
	}
	if input.UserID == "" || input.DeviceUID == "" || input.DeviceModel == "" || input.Transport == "" {
		return domain.ProvisioningSession{}, false, errors.New("user_id, device_uid, device_model and transport are required")
	}
	if input.Transport != "ble" && input.Transport != "nfc" {
		return domain.ProvisioningSession{}, false, errors.New("transport must be ble or nfc")
	}
	if len(input.UserID) > 128 || len(input.DeviceUID) > 256 || len(input.DeviceModel) > 128 {
		return domain.ProvisioningSession{}, false, errors.New("input field exceeds maximum length")
	}
	fingerprint, err := canonicalCreateFingerprint(input)
	if err != nil {
		return domain.ProvisioningSession{}, false, fmt.Errorf("fingerprint session creation request: %w", err)
	}
	id, err := randomID("ps")
	if err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	now := s.now()
	result := domain.ProvisioningSession{ID: id, IdempotencyKey: idempotencyKey, RequestFingerprint: fingerprint, UserID: input.UserID, DeviceUID: input.DeviceUID, DeviceModel: input.DeviceModel, Transport: input.Transport, State: domain.StateCreated, Version: 1, Correlation: id, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	stored, created, err := s.repo.Create(ctx, result)
	if err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	// PostgreSQL persists only a hash of the device UID. The exact request has
	// already been fingerprint-verified by Create, so echo its UID in this
	// response without adding the raw value to durable storage.
	stored.DeviceUID = input.DeviceUID
	if created {
		s.record(ctx, audit.Event{SessionID: result.ID, Type: "PROVISIONING_SESSION_CREATED", Result: "SUCCESS", At: now})
	}
	if !created && stored.DeviceID != "" {
		return stored, true, nil
	}
	if s.devices != nil {
		device, registryErr := s.devices.EnsureDevice(ctx, input.UserID, input.DeviceUID, input.DeviceModel, input.Transport, now)
		if registryErr != nil {
			return stored, !created, registryErr
		}
		if stored.DeviceID != device.ID {
			stored.DeviceID = device.ID
			updated, saveErr := s.repo.Save(ctx, stored)
			if saveErr != nil {
				latest, getErr := s.repo.Get(ctx, stored.ID)
				if getErr == nil && latest.DeviceID == device.ID {
					latest.DeviceUID = input.DeviceUID
					stored = latest
				} else {
					return stored, !created, saveErr
				}
			} else {
				stored = updated
			}
		}
	}
	return stored, !created, nil
}

func canonicalCreateFingerprint(input CreateInput) ([]byte, error) {
	canonical := struct {
		Version     int    `json:"version"`
		UserID      string `json:"user_id"`
		DeviceUID   string `json:"device_uid"`
		DeviceModel string `json:"device_model"`
		Transport   string `json:"transport"`
	}{Version: 1, UserID: input.UserID, DeviceUID: input.DeviceUID, DeviceModel: input.DeviceModel, Transport: input.Transport}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(encoded)
	return fingerprint[:], nil
}
func (s *Service) Discover(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateDeviceDiscovered)
}
func (s *Service) TransitionToAttested(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateDeviceAttested)
}
func (s *Service) Attest(ctx context.Context, id, deviceResponse string) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	challenge, err := s.crypto.CreateChallenge(ctx, current.DeviceUID, current.ID)
	if err != nil {
		return current, err
	}
	if err := s.crypto.VerifyDeviceResponse(ctx, current.DeviceUID, challenge, deviceResponse); err != nil {
		return current, err
	}
	return s.transition(ctx, id, domain.StateDeviceAttested)
}
func (s *Service) Authenticate(ctx context.Context, id, proof string) (domain.ProvisioningSession, error) {
	if proof == "" {
		return domain.ProvisioningSession{}, ErrInvalidStageInput
	}
	return s.callAndTransition(ctx, id, domain.StateDeviceAttested, domain.StateSessionAuthenticated, func(session domain.ProvisioningSession) error {
		if s.authenticator == nil {
			return ErrStageUnavailable
		}
		return s.authenticator.AuthenticateSession(ctx, session, proof)
	})
}
func (s *Service) RequestToken(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	if s.tokens == nil {
		return domain.ProvisioningSession{}, ErrStageUnavailable
	}
	now := s.now()
	claim, err := s.repo.ClaimTokenRequest(ctx, id, now)
	if err != nil {
		return claim.Session, err
	}
	if !claim.Claimed {
		switch claim.Operation.Status {
		case domain.TokenRequestSucceeded:
			if claim.Session.State == domain.StateTokenRequesting {
				return claim.Session, domain.ErrSessionExpired
			}
			return claim.Session, nil
		case domain.TokenRequestUnknown:
			return claim.Session, domain.ErrTokenRequestOutcomeUnknown
		default:
			return claim.Session, domain.ErrTokenRequestInProgress
		}
	}
	s.record(ctx, audit.Event{SessionID: id, Type: "TOKEN_REQUEST_CLAIMED", Result: "PENDING", Reason: "TOKEN_REQUEST_CLAIMED", At: now})
	providerReference, callErr := s.tokens.RequestToken(ctx, id, claim.Operation.IdempotencyKey)
	if callErr != nil {
		return s.markTokenRequestUnknown(ctx, id, "PROVIDER_CALL_OUTCOME_UNKNOWN", claim.Session)
	}
	if strings.TrimSpace(providerReference) == "" {
		return s.markTokenRequestUnknown(ctx, id, "EMPTY_PROVIDER_REFERENCE", claim.Session)
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	updated, changed, completeErr := s.repo.CompleteTokenRequest(persistCtx, id, providerReference, s.now())
	if completeErr != nil {
		if errors.Is(completeErr, domain.ErrSessionExpired) || errors.Is(completeErr, domain.ErrTokenRequestConflict) {
			return updated, completeErr
		}
		// The provider may have created a token even if local persistence failed.
		// A local retry with the same reference is safe; a second provider call is not.
		updated, changed, completeErr = s.repo.CompleteTokenRequest(persistCtx, id, providerReference, s.now())
		if completeErr != nil {
			return s.markTokenRequestUnknown(persistCtx, id, "PROVIDER_RESULT_PERSISTENCE_UNKNOWN", updated)
		}
	}
	if changed {
		s.record(ctx, audit.Event{SessionID: id, Type: "TOKEN_REQUESTED", Result: "SUCCESS", Reason: "TOKEN_REQUEST_COMPLETED", At: s.now()})
	}
	return updated, nil
}

func (s *Service) markTokenRequestUnknown(ctx context.Context, id, errorCode string, fallback domain.ProvisioningSession) (domain.ProvisioningSession, error) {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	claim, err := s.repo.MarkTokenRequestUnknown(persistCtx, id, errorCode, s.now())
	if err != nil {
		return fallback, domain.ErrTokenRequestOutcomeUnknown
	}
	if claim.Operation.Status == domain.TokenRequestSucceeded && claim.Session.State != domain.StateTokenRequesting {
		return claim.Session, nil
	}
	s.record(persistCtx, audit.Event{SessionID: id, Type: "TOKEN_REQUEST_OUTCOME_UNKNOWN", Result: "UNKNOWN", Reason: errorCode, At: s.now()})
	return claim.Session, domain.ErrTokenRequestOutcomeUnknown
}
func (s *Service) ReceiveToken(ctx context.Context, event TokenWebhook) (domain.ProvisioningSession, error) {
	if event.SessionID == "" || event.TokenReference == "" || strings.TrimSpace(event.EventID) == "" || event.EventID != strings.TrimSpace(event.EventID) || len(event.EventID) > 256 || strings.ContainsAny(event.EventID, "\x00\r\n") {
		return domain.ProvisioningSession{}, ErrInvalidStageInput
	}
	current, err := s.repo.Get(ctx, event.SessionID)
	if err != nil {
		return current, err
	}
	if (current.State == domain.StateTokenRequested || current.State == domain.StateTokenRequesting) && current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if current.State == domain.StateTokenRequesting || (current.TokenReference == event.TokenReference && (current.State == domain.StateTokenRequested || current.State == domain.StateTokenReceived || current.State == domain.StatePayloadWrapped || current.State == domain.StateTransferStarted || current.State == domain.StateTransferred || current.State == domain.StateDeviceVerified || current.State == domain.StateCompleted)) {
		updated, changed, receiveErr := s.repo.ReceiveTokenWebhook(ctx, domain.TokenWebhookEvent{EventID: event.EventID, SessionID: event.SessionID, TokenReference: event.TokenReference}, s.now())
		if receiveErr == nil && changed {
			s.record(ctx, audit.Event{SessionID: event.SessionID, Type: "TOKEN_RECEIVED", Result: "SUCCESS", At: s.now()})
		}
		return updated, receiveErr
	}
	if current.State == domain.StateTokenRequested && current.TokenReference != event.TokenReference {
		return s.fail(ctx, current, "TOKEN_REFERENCE_MISMATCH", ErrTokenNotReceived)
	}
	return current, domain.ErrInvalidTransition
}
func (s *Service) WrapPayload(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	if s.wrapper == nil {
		return domain.ProvisioningSession{}, ErrStageUnavailable
	}
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := requireState(current, domain.StateTokenReceived); err != nil {
		return current, err
	}
	wrapped, err := s.wrapper.WrapPayload(ctx, current, current.TokenReference)
	if err != nil {
		return s.fail(ctx, current, "PAYLOAD_WRAP_FAILED", err)
	}
	if wrapped == "" {
		return s.fail(ctx, current, "WRAPPED_PAYLOAD_EMPTY", ErrInvalidStageInput)
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	current.WrappedPayload = wrapped
	current.State = domain.StatePayloadWrapped
	return s.save(ctx, current, "PAYLOAD_WRAPPED")
}
func (s *Service) TransferAPDU(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	if s.transfer == nil {
		return domain.ProvisioningSession{}, ErrStageUnavailable
	}
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := requireState(current, domain.StatePayloadWrapped); err != nil {
		return current, err
	}
	current.State = domain.StateTransferStarted
	current, err = s.save(ctx, current, "APDU_TRANSFER_STARTED")
	if err != nil {
		return current, err
	}
	if err := s.transfer.Transfer(ctx, current, current.WrappedPayload); err != nil {
		return s.fail(ctx, current, "APDU_TRANSFER_FAILED", err)
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	current.State = domain.StateTransferred
	return s.save(ctx, current, "APDU_TRANSFERRED")
}
func (s *Service) VerifyDevice(ctx context.Context, id, proof string) (domain.ProvisioningSession, error) {
	if proof == "" {
		return domain.ProvisioningSession{}, ErrInvalidStageInput
	}
	return s.callAndTransition(ctx, id, domain.StateTransferred, domain.StateDeviceVerified, func(session domain.ProvisioningSession) error {
		if s.deviceVerifier == nil {
			return ErrStageUnavailable
		}
		return s.deviceVerifier.VerifyDevice(ctx, session, proof)
	})
}
func (s *Service) Complete(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateCompleted)
}
func (s *Service) Fail(ctx context.Context, id, code string) (domain.ProvisioningSession, error) {
	if code == "" {
		return domain.ProvisioningSession{}, ErrInvalidStageInput
	}
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := current.Transition(domain.StateFailed); err != nil {
		return current, err
	}
	current.FailureCode = code
	return s.save(ctx, current, "PROVISIONING_FAILED")
}
func (s *Service) callAndTransition(ctx context.Context, id string, expected, next domain.ProvisioningState, call func(domain.ProvisioningSession) error) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if err := requireState(current, expected); err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := call(current); err != nil {
		return s.fail(ctx, current, "STAGE_VERIFICATION_FAILED", err)
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	current.State = next
	return s.save(ctx, current, string(next))
}
func (s *Service) transition(ctx context.Context, id string, next domain.ProvisioningState) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := current.Transition(next); err != nil {
		return current, err
	}
	return s.save(ctx, current, string(next))
}
func requireState(s domain.ProvisioningSession, expected domain.ProvisioningState) error {
	if s.State != expected {
		return fmt.Errorf("%w: expected %s, got %s", domain.ErrInvalidTransition, expected, s.State)
	}
	return nil
}
func (s *Service) save(ctx context.Context, current domain.ProvisioningSession, eventType string) (domain.ProvisioningSession, error) {
	updated, err := s.repo.Save(ctx, current)
	if err != nil {
		return current, err
	}
	s.record(ctx, audit.Event{SessionID: current.ID, Type: eventType, Result: "SUCCESS", At: s.now()})
	return updated, nil
}
func (s *Service) fail(ctx context.Context, current domain.ProvisioningSession, code string, cause error) (domain.ProvisioningSession, error) {
	if current.Expired(s.now()) {
		return current, domain.ErrSessionExpired
	}
	if err := current.Transition(domain.StateFailed); err != nil {
		return current, err
	}
	current.FailureCode = code
	_, saveErr := s.repo.Save(ctx, current)
	s.record(ctx, audit.Event{SessionID: current.ID, Type: "PROVISIONING_FAILED", Result: "FAILURE", Reason: code, At: s.now()})
	if saveErr != nil {
		return current, fmt.Errorf("%w: %v", cause, saveErr)
	}
	return current, fmt.Errorf("%s: %w", code, cause)
}
func (s *Service) record(ctx context.Context, event audit.Event) {
	if s.audit != nil {
		_ = s.audit.Record(ctx, event)
	}
}
func randomID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

var _ Repository = (*memory.SessionRepository)(nil)
