package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
)

// DeviceRepository is the durable registry boundary used by the device service.
type DeviceRepository interface {
	Create(context.Context, domain.Device) error
	Get(context.Context, string) (domain.Device, error)
	Save(context.Context, domain.Device) error
}

// DeviceService owns registry lifecycle changes and is the only service allowed
// to bind a verified attestation to a durable device aggregate.
type DeviceService struct {
	repo DeviceRepository
	now  func() time.Time
}

func NewDeviceService(repo DeviceRepository) *DeviceService {
	return &DeviceService{repo: repo, now: time.Now}
}

func (s *DeviceService) Get(ctx context.Context, id string) (domain.Device, error) {
	if s == nil || s.repo == nil {
		return domain.Device{}, errors.New("device registry unavailable")
	}
	return s.repo.Get(ctx, strings.TrimSpace(id))
}

// RegisterFromSession creates the discovered aggregate using only a hashed
// device identity. The raw identifier is never sent to the repository.
func (s *DeviceService) RegisterFromSession(ctx context.Context, session domain.ProvisioningSession) (domain.Device, error) {
	if s == nil || s.repo == nil {
		return domain.Device{}, errors.New("device registry unavailable")
	}
	identityHash := sessionIdentityHash(session)
	device, err := domain.NewDevice(deviceID(identityHash), session.UserID, identityHash, session.DeviceModel, session.Transport, s.now())
	if err != nil {
		return domain.Device{}, err
	}
	if err := s.repo.Create(ctx, device); err != nil {
		return domain.Device{}, fmt.Errorf("register device: %w", err)
	}
	return device, nil
}

// RecordVerifiedAttestation creates the device aggregate if necessary, records
// the provider result, and activates the device only after successful durable
// persistence validation. Existing suspended, revoked, or retired devices are
// not silently reactivated.
func (s *DeviceService) RecordVerifiedAttestation(ctx context.Context, session domain.ProvisioningSession, result attestation.VerifiedResult) (domain.Device, error) {
	if s == nil || s.repo == nil {
		return domain.Device{}, errors.New("device registry unavailable")
	}
	identityHash := sessionIdentityHash(session)
	id := deviceID(identityHash)
	device, err := s.repo.Get(ctx, id)
	if errors.Is(err, domain.ErrDeviceNotFound) {
		device, err = s.RegisterFromSession(ctx, session)
	}
	if err != nil {
		return domain.Device{}, err
	}
	at := s.now()
	if device.State == domain.DeviceStateDiscovered {
		if err := device.Transition(domain.DeviceStatePendingAttestation, at); err != nil {
			return domain.Device{}, err
		}
	}
	if device.State == domain.DeviceStateSuspended {
		return domain.Device{}, fmt.Errorf("%w: device is suspended", domain.ErrInvalidDeviceTransition)
	}
	if device.State != domain.DeviceStatePendingAttestation && device.State != domain.DeviceStateActive {
		return domain.Device{}, fmt.Errorf("%w: device is %s", domain.ErrInvalidDeviceTransition, device.State)
	}
	if err := device.RecordAttestation(result.Provider, result.KeyID, result.TrustLevel, result.Counter, at); err != nil {
		return domain.Device{}, err
	}
	if device.State == domain.DeviceStatePendingAttestation {
		if err := device.Transition(domain.DeviceStateActive, at); err != nil {
			return domain.Device{}, err
		}
	}
	if err := s.repo.Save(ctx, device); err != nil {
		return domain.Device{}, fmt.Errorf("persist verified device: %w", err)
	}
	return device, nil
}

func (s *DeviceService) RegisterVerifiedAttestation(ctx context.Context, session domain.ProvisioningSession, result attestation.VerifiedResult) error {
	_, err := s.RecordVerifiedAttestation(ctx, session, result)
	return err
}

func (s *DeviceService) Transition(ctx context.Context, id string, next domain.DeviceLifecycleState) (domain.Device, error) {
	if s == nil || s.repo == nil {
		return domain.Device{}, errors.New("device registry unavailable")
	}
	device, err := s.repo.Get(ctx, strings.TrimSpace(id))
	if err != nil {
		return domain.Device{}, err
	}
	if err := device.Transition(next, s.now()); err != nil {
		return domain.Device{}, err
	}
	if err := s.repo.Save(ctx, device); err != nil {
		return domain.Device{}, fmt.Errorf("persist device transition: %w", err)
	}
	return device, nil
}

func (s *DeviceService) RevokeAttestation(ctx context.Context, id, provider, keyID, reason string) (domain.Device, error) {
	if s == nil || s.repo == nil {
		return domain.Device{}, errors.New("device registry unavailable")
	}
	device, err := s.repo.Get(ctx, strings.TrimSpace(id))
	if err != nil {
		return domain.Device{}, err
	}
	if err := device.RevokeAttestation(provider, keyID, reason, s.now()); err != nil {
		return domain.Device{}, err
	}
	if err := s.repo.Save(ctx, device); err != nil {
		return domain.Device{}, fmt.Errorf("persist device attestation revocation: %w", err)
	}
	return device, nil
}

func hashDeviceIdentity(deviceUID string) string {
	sum := sha256.Sum256([]byte(deviceUID))
	return hex.EncodeToString(sum[:])
}

func sessionIdentityHash(session domain.ProvisioningSession) string {
	if session.DeviceIdentityHash != "" {
		return session.DeviceIdentityHash
	}
	return hashDeviceIdentity(session.DeviceUID)
}

func deviceID(identityHash string) string { return "dev_" + identityHash }
