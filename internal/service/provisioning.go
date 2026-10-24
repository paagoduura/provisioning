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

type AuditPort interface {
	Record(context.Context, audit.Event) error
}

type CreateInput struct{ UserID, DeviceUID, DeviceModel, Transport string }

type Service struct {
	repo   Repository
	crypto CryptoPort
	tokens TokenPort
	audit  AuditPort
	now    func() time.Time
}

func New(repo Repository, crypto CryptoPort, tokens TokenPort, auditSink AuditPort) *Service {
	return &Service{repo: repo, crypto: crypto, tokens: tokens, audit: auditSink, now: time.Now}
}

func (s *Service) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.repo.Get(ctx, id)
}

func (s *Service) Create(ctx context.Context, input CreateInput, idempotencyKey string) (domain.ProvisioningSession, bool, error) {
	if idempotencyKey == "" {
		return domain.ProvisioningSession{}, false, errors.New("idempotency key is required")
	}
	if existing, err := s.repo.FindByIdempotencyKey(ctx, idempotencyKey); err == nil {
		return existing, true, nil
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
	if err := s.repo.Save(ctx, result); err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	if err := s.repo.SaveIdempotencyKey(ctx, idempotencyKey, id); err != nil {
		return domain.ProvisioningSession{}, false, err
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Event{SessionID: result.ID, Type: "PROVISIONING_SESSION_CREATED", Result: "SUCCESS", At: now})
	}
	return result, false, nil
}

func (s *Service) Discover(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	return s.transition(ctx, id, domain.StateDeviceDiscovered)
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
