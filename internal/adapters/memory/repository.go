package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/paagoduura/provisioning/internal/domain"
)

var ErrNotFound = errors.New("session not found")

type SessionRepository struct {
	mu             sync.RWMutex
	sessions       map[string]domain.ProvisioningSession
	idempotencyKey map[string]string
}

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{sessions: make(map[string]domain.ProvisioningSession), idempotencyKey: make(map[string]string)}
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

func (r *SessionRepository) Save(ctx context.Context, s domain.ProvisioningSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s.ID] = s
	return nil
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
