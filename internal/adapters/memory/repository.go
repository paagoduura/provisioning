package memory

import (
	"context"
	"sync"

	"github.com/paagoduura/provisioning/internal/domain"
)

var ErrNotFound = domain.ErrSessionNotFound

type SessionRepository struct {
	mu             sync.RWMutex
	sessions       map[string]domain.ProvisioningSession
	idempotencyKey map[string]string
}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{sessions: make(map[string]domain.ProvisioningSession), idempotencyKey: make(map[string]string)}
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
