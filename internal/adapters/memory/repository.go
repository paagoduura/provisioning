package memory

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/paagoduura/provisioning/internal/domain"
)

var ErrNotFound = domain.ErrSessionNotFound

type SessionRepository struct {
	mu              sync.RWMutex
	sessions        map[string]domain.ProvisioningSession
	idempotencyKey  map[string]string
	webhookEvents   map[string]storedWebhookEvent
	webhookPayloads map[string]struct{}
}

type storedWebhookEvent struct {
	sessionID string
	payload   [32]byte
}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{sessions: make(map[string]domain.ProvisioningSession), idempotencyKey: make(map[string]string), webhookEvents: make(map[string]storedWebhookEvent), webhookPayloads: make(map[string]struct{})}
}

func (r *SessionRepository) Create(ctx context.Context, s domain.ProvisioningSession) (domain.ProvisioningSession, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.idempotencyKey[s.IdempotencyKey]; ok {
		if existing, ok := r.sessions[id]; ok {
			return existing, false, nil
		}
	}
	if s.Version == 0 {
		s.Version = 1
	}
	r.sessions[s.ID] = s
	r.idempotencyKey[s.IdempotencyKey] = s.ID
	return s, true, nil
}

func (r *SessionRepository) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[id]
	if !ok {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	return s, nil
}

func (r *SessionRepository) Save(ctx context.Context, s domain.ProvisioningSession) (domain.ProvisioningSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.sessions[s.ID]
	if !ok {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	if s.Version == 0 || s.Version != existing.Version {
		return domain.ProvisioningSession{}, domain.ErrConcurrentUpdate
	}
	s.Version++
	r.sessions[s.ID] = s
	return s, nil
}

// ReceiveTokenWebhook commits event identity and the state change under one
// lock. Reuse of an event identifier is idempotent only for identical content.
func (r *SessionRepository) ReceiveTokenWebhook(_ context.Context, event domain.TokenWebhookEvent, _ time.Time) (domain.ProvisioningSession, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload := sha256.Sum256([]byte(event.SessionID + "\x00" + event.TokenReference))
	if previous, exists := r.webhookEvents[event.EventID]; exists {
		if previous.sessionID != event.SessionID || previous.payload != payload {
			return domain.ProvisioningSession{}, false, domain.ErrWebhookEventConflict
		}
		session, ok := r.sessions[event.SessionID]
		if !ok {
			return domain.ProvisioningSession{}, false, ErrNotFound
		}
		return session, false, nil
	}
	payloadKey := event.SessionID + "\x00" + string(payload[:])
	if _, exists := r.webhookPayloads[payloadKey]; exists {
		session, ok := r.sessions[event.SessionID]
		if !ok {
			return domain.ProvisioningSession{}, false, ErrNotFound
		}
		return session, false, nil
	}
	session, ok := r.sessions[event.SessionID]
	if !ok {
		return domain.ProvisioningSession{}, false, ErrNotFound
	}
	if session.TokenReference != event.TokenReference {
		return domain.ProvisioningSession{}, false, domain.ErrInvalidTransition
	}
	changed := false
	if session.State == domain.StateTokenRequested {
		session.State = domain.StateTokenReceived
		session.Version++
		r.sessions[event.SessionID] = session
		changed = true
	} else if session.State != domain.StateTokenReceived {
		return domain.ProvisioningSession{}, false, domain.ErrInvalidTransition
	}
	r.webhookEvents[event.EventID] = storedWebhookEvent{sessionID: event.SessionID, payload: payload}
	r.webhookPayloads[payloadKey] = struct{}{}
	return session, changed, nil
}

func (r *SessionRepository) FindByIdempotencyKey(ctx context.Context, key string) (domain.ProvisioningSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.idempotencyKey[key]
	if !ok {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	s, ok := r.sessions[id]
	if !ok {
		return domain.ProvisioningSession{}, ErrNotFound
	}
	return s, nil
}

func (r *SessionRepository) SaveIdempotencyKey(ctx context.Context, key, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.idempotencyKey[key] = id
	return nil
}
