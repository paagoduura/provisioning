package memory

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/domain"
)

var errTokenRequestOperationMissing = errors.New("token request operation is missing")

func (r *SessionRepository) ClaimTokenRequest(_ context.Context, sessionID string, now time.Time) (domain.TokenRequestClaim, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, ok := r.sessions[sessionID]
	if !ok {
		return domain.TokenRequestClaim{}, ErrNotFound
	}
	switch session.State {
	case domain.StateSessionAuthenticated:
		if session.Expired(now) {
			return domain.TokenRequestClaim{Session: session}, domain.ErrSessionExpired
		}
		if _, exists := r.tokenRequests[sessionID]; exists {
			return domain.TokenRequestClaim{Session: session}, domain.ErrTokenRequestOutcomeUnknown
		}
		operation := domain.TokenRequestOperation{SessionID: sessionID, IdempotencyKey: domain.TokenRequestIdempotencyKey(sessionID), Status: domain.TokenRequestPending, CreatedAt: now, UpdatedAt: now}
		session.State = domain.StateTokenRequesting
		session.Version++
		r.sessions[sessionID] = session
		r.tokenRequests[sessionID] = operation
		return domain.TokenRequestClaim{Session: session, Operation: operation, Claimed: true}, nil
	case domain.StateTokenRequesting:
		operation, exists := r.tokenRequests[sessionID]
		if !exists {
			return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
		}
		if session.Expired(now) && operation.Status == domain.TokenRequestPending {
			operation.Status = domain.TokenRequestUnknown
			operation.LastErrorCode = "SESSION_EXPIRED_DURING_PROVIDER_REQUEST"
			operation.UpdatedAt = now
			r.tokenRequests[sessionID] = operation
		}
		return domain.TokenRequestClaim{Session: session, Operation: operation}, nil
	case domain.StateTokenRequested, domain.StateTokenReceived, domain.StatePayloadWrapped, domain.StateTransferStarted, domain.StateTransferred, domain.StateDeviceVerified, domain.StateCompleted:
		if session.TokenReference == "" {
			return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
		}
		operation, exists := r.tokenRequests[sessionID]
		if !exists {
			operation = domain.TokenRequestOperation{SessionID: sessionID, IdempotencyKey: domain.TokenRequestIdempotencyKey(sessionID), Status: domain.TokenRequestSucceeded, ProviderReference: session.TokenReference}
		} else if operation.Status != domain.TokenRequestSucceeded || operation.ProviderReference != session.TokenReference {
			return domain.TokenRequestClaim{Session: session, Operation: operation}, domain.ErrTokenRequestOutcomeUnknown
		}
		return domain.TokenRequestClaim{Session: session, Operation: operation}, nil
	default:
		return domain.TokenRequestClaim{Session: session}, domain.ErrInvalidTransition
	}
}

func (r *SessionRepository) MarkTokenRequestUnknown(_ context.Context, sessionID, errorCode string, now time.Time) (domain.TokenRequestClaim, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[sessionID]
	if !ok {
		return domain.TokenRequestClaim{}, ErrNotFound
	}
	operation, ok := r.tokenRequests[sessionID]
	if !ok {
		return domain.TokenRequestClaim{Session: session}, errTokenRequestOperationMissing
	}
	if operation.Status == domain.TokenRequestPending {
		operation.Status = domain.TokenRequestUnknown
		operation.LastErrorCode = boundedErrorCode(errorCode)
		operation.UpdatedAt = now
		r.tokenRequests[sessionID] = operation
	}
	return domain.TokenRequestClaim{Session: session, Operation: operation}, nil
}

func (r *SessionRepository) CompleteTokenRequest(_ context.Context, sessionID, providerReference string, now time.Time) (domain.ProvisioningSession, bool, error) {
	if strings.TrimSpace(providerReference) == "" {
		return domain.ProvisioningSession{}, false, domain.ErrTokenRequestOutcomeUnknown
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[sessionID]
	if !ok {
		return domain.ProvisioningSession{}, false, ErrNotFound
	}
	operation, ok := r.tokenRequests[sessionID]
	if !ok {
		return session, false, errTokenRequestOperationMissing
	}
	if operation.Status == domain.TokenRequestSucceeded {
		if operation.ProviderReference != providerReference {
			return session, false, domain.ErrTokenRequestConflict
		}
		if session.TokenReference != "" && session.TokenReference != providerReference {
			return session, false, domain.ErrTokenRequestConflict
		}
		if session.State == domain.StateTokenRequesting && session.Expired(now) {
			return session, false, domain.ErrSessionExpired
		}
		return session, false, nil
	}
	if session.State == domain.StateTokenReceived && session.TokenReference == providerReference {
		operation.Status = domain.TokenRequestSucceeded
		operation.ProviderReference = providerReference
		operation.LastErrorCode = ""
		operation.UpdatedAt = now
		r.tokenRequests[sessionID] = operation
		return session, false, nil
	}
	if session.State != domain.StateTokenRequesting || (operation.Status != domain.TokenRequestPending && operation.Status != domain.TokenRequestUnknown) {
		return session, false, domain.ErrInvalidTransition
	}
	operation.Status = domain.TokenRequestSucceeded
	operation.ProviderReference = providerReference
	operation.LastErrorCode = ""
	operation.UpdatedAt = now
	r.tokenRequests[sessionID] = operation
	if session.Expired(now) {
		return session, false, domain.ErrSessionExpired
	}
	session.TokenReference = providerReference
	session.State = domain.StateTokenRequested
	session.Version++
	r.sessions[sessionID] = session
	return session, true, nil
}

func boundedErrorCode(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		return value[:64]
	}
	return value
}
