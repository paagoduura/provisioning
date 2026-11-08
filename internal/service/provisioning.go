package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/audit"
	"github.com/paagoduura/provisioning/internal/domain"
)

type Repository interface {
	Create(context.Context, domain.ProvisioningSession) (domain.ProvisioningSession, bool, error)
	Get(context.Context, string) (domain.ProvisioningSession, error)
	Save(context.Context, domain.ProvisioningSession) error
	FindByIdempotencyKey(context.Context, string) (domain.ProvisioningSession, error)
	SaveIdempotencyKey(context.Context, string, string) error
}

type CryptoPort interface {
	CreateChallenge(context.Context, string, string) (string, error)
	VerifyDeviceResponse(context.Context, string, string, string) error
}

type TokenPort interface {
	RequestToken(context.Context, string) (string, error)
	WrapToken(context.Context, string, string) (string, error)
}

var ErrPaymentIntegrationNotConfigured = errors.New("payment integration is not configured")

type PersonalizationPort interface {
	Transfer(context.Context, string, string) error
	Verify(context.Context, string, string) error
}

type AuditPort interface {
	Record(context.Context, audit.Event) error
}

type CreateInput struct{ UserID, DeviceUID, DeviceModel, Transport string }

type Service struct {
	repo         Repository
	crypto       CryptoPort
	tokens       TokenPort
	personalizer PersonalizationPort
	audit        AuditPort
	now          func() time.Time
}

func New(repo Repository, crypto CryptoPort, tokens TokenPort, auditSink AuditPort) *Service {
	return &Service{repo: repo, crypto: crypto, tokens: tokens, audit: auditSink, now: time.Now}
}

func (s *Service) SetPersonalizer(personalizer PersonalizationPort) { s.personalizer = personalizer }

func (s *Service) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.repo.Get(ctx, id)
}

func (s *Service) Create(ctx context.Context, input CreateInput, idempotencyKey string) (domain.ProvisioningSession, bool, error) {
	if idempotencyKey == "" {
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
	id, err := randomID("ps")
	if err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	now := s.now()
	result := domain.ProvisioningSession{ID: id, IdempotencyKey: idempotencyKey, UserID: input.UserID, DeviceUID: input.DeviceUID, DeviceModel: input.DeviceModel, Transport: input.Transport, State: domain.StateCreated, Correlation: id, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	stored, created, err := s.repo.Create(ctx, result)
	if err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	if !created {
		return stored, true, nil
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Event{SessionID: result.ID, Type: "PROVISIONING_SESSION_CREATED", Result: "SUCCESS", At: now})
	}
	return result, false, nil
}

func (s *Service) Discover(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateDeviceDiscovered)
}

func (s *Service) TransitionToAttested(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateDeviceAttested)
}

func (s *Service) AuthenticateSession(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateSessionAuthenticated)
}

// ProvisionPayment executes the certified-integration boundary in a durable,
// retry-safe order. Provider and secure-element implementations are injected;
// production uses fail-closed adapters until their approved contracts exist.
func (s *Service) ProvisionPayment(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, fmt.Errorf("session expired")
	}
	if current.State == domain.StateCompleted {
		return current, nil
	}
	if current.State != domain.StateSessionAuthenticated && current.State != domain.StateTokenRequested && current.State != domain.StateTokenReceived && current.State != domain.StatePayloadWrapped && current.State != domain.StateTransferStarted && current.State != domain.StateTransferred && current.State != domain.StateDeviceVerified {
		return current, fmt.Errorf("payment provisioning requires session authentication: %w", domain.ErrInvalidTransition)
	}
	if s.tokens == nil || s.personalizer == nil {
		failed, _ := s.failProvisioning(ctx, current, "PAYMENT_INTEGRATION_NOT_CONFIGURED")
		return failed, ErrPaymentIntegrationNotConfigured
	}
	if current.State == domain.StateSessionAuthenticated {
		if current, err = s.transitionCurrent(ctx, current, domain.StateTokenRequested); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StateTokenRequested {
		tokenRef, requestErr := s.tokens.RequestToken(ctx, current.ID)
		if requestErr != nil {
			return s.failProvisioning(ctx, current, "TOKEN_REQUEST_FAILED")
		}
		if tokenRef == "" {
			return s.failProvisioning(ctx, current, "TOKEN_RESPONSE_INVALID")
		}
		current.PaymentTokenRef = tokenRef
		if _, err := s.transitionCurrent(ctx, current, domain.StateTokenReceived); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StateTokenReceived {
		payload, wrapErr := s.tokens.WrapToken(ctx, current.DeviceUID, current.PaymentTokenRef)
		if wrapErr != nil {
			return s.failProvisioning(ctx, current, "PAYLOAD_WRAP_FAILED")
		}
		if payload == "" {
			return s.failProvisioning(ctx, current, "PAYLOAD_INVALID")
		}
		current.WrappedPayloadRef = payload
		if _, err := s.transitionCurrent(ctx, current, domain.StatePayloadWrapped); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StatePayloadWrapped {
		if err := s.personalizer.Transfer(ctx, current.DeviceUID, current.WrappedPayloadRef); err != nil {
			return s.failProvisioning(ctx, current, "PERSONALIZATION_FAILED")
		}
		if _, err := s.transitionCurrent(ctx, current, domain.StateTransferStarted); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StateTransferStarted {
		if _, err := s.transitionCurrent(ctx, current, domain.StateTransferred); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StateTransferred {
		if err := s.personalizer.Verify(ctx, current.DeviceUID, current.WrappedPayloadRef); err != nil {
			return s.failProvisioning(ctx, current, "DEVICE_VERIFICATION_FAILED")
		}
		if _, err := s.transitionCurrent(ctx, current, domain.StateDeviceVerified); err != nil {
			return current, err
		}
		current, err = s.repo.Get(ctx, id)
		if err != nil {
			return current, err
		}
	}
	if current.State == domain.StateDeviceVerified {
		return s.transitionCurrent(ctx, current, domain.StateCompleted)
	}
	return current, nil
}

func (s *Service) failProvisioning(ctx context.Context, current domain.ProvisioningSession, code string) (domain.ProvisioningSession, error) {
	current.FailureCode = code
	if current.State != domain.StateFailed {
		_ = current.Transition(domain.StateFailed)
	}
	if err := s.repo.Save(ctx, current); err != nil {
		return current, err
	}
	return current, errors.New(code)
}

func (s *Service) transitionCurrent(ctx context.Context, current domain.ProvisioningSession, next domain.ProvisioningState) (domain.ProvisioningSession, error) {
	if err := current.Transition(next); err != nil {
		return current, err
	}
	if err := s.repo.Save(ctx, current); err != nil {
		return current, err
	}
	return current, nil
}

func (s *Service) Attest(ctx context.Context, id, deviceResponse string) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, fmt.Errorf("session expired")
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

func (s *Service) transition(ctx context.Context, id string, next domain.ProvisioningState) (domain.ProvisioningSession, error) {
	current, err := s.repo.Get(ctx, id)
	if err != nil {
		return current, err
	}
	if current.Expired(s.now()) {
		return current, fmt.Errorf("session expired")
	}
	if err := current.Transition(next); err != nil {
		return current, err
	}
	if err := s.repo.Save(ctx, current); err != nil {
		return current, err
	}
	return current, nil
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

var _ Repository = (*memory.SessionRepository)(nil)
