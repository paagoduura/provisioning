package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/domain"
)

type stageAuth struct{}

func (stageAuth) AuthenticateSession(context.Context, domain.ProvisioningSession, string) error {
	return nil
}

type stageVerifier struct{}

func (stageVerifier) VerifyDevice(context.Context, domain.ProvisioningSession, string) error {
	return nil
}

type stageWrapper struct{}

func (stageWrapper) WrapPayload(context.Context, domain.ProvisioningSession, string) (string, error) {
	return "d3JhcHBlZA", nil
}

type callbackWrapper func(context.Context, domain.ProvisioningSession, string) (string, error)

func (f callbackWrapper) WrapPayload(ctx context.Context, session domain.ProvisioningSession, reference string) (string, error) {
	return f(ctx, session, reference)
}

type stageTransfer struct{}

func (stageTransfer) Transfer(context.Context, domain.ProvisioningSession, string) error { return nil }

type callbackTransfer func(context.Context, domain.ProvisioningSession, string) error

func (f callbackTransfer) Transfer(ctx context.Context, session domain.ProvisioningSession, payload string) error {
	return f(ctx, session, payload)
}

func TestRemainingStagesAdvanceExactlyOnce(t *testing.T) {
	repo := memory.NewSessionRepository()
	svc := New(repo, mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	svc.SetSessionAuthenticator(stageAuth{})
	svc.SetDeviceVerifier(stageVerifier{})
	svc.SetPayloadWrapper(stageWrapper{})
	svc.SetAPDUTransport(stageTransfer{})
	ctx := context.Background()
	session, _, err := svc.Create(ctx, CreateInput{UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble"}, "stage-sequence")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Discover(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Attest(ctx, session.ID, "device-response"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(ctx, session.ID, "session-proof"); err != nil {
		t.Fatal(err)
	}
	requested, err := svc.RequestToken(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ReceiveToken(ctx, TokenWebhook{SessionID: session.ID, TokenReference: requested.TokenReference, EventID: "event-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.WrapPayload(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.TransferAPDU(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.VerifyDevice(ctx, session.ID, "device-proof"); err != nil {
		t.Fatal(err)
	}
	completed, err := svc.Complete(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != domain.StateCompleted {
		t.Fatalf("state=%s want=%s", completed.State, domain.StateCompleted)
	}
}

func TestTokenWebhookMismatchFailsClosed(t *testing.T) {
	repo := memory.NewSessionRepository()
	svc := New(repo, mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	svc.SetSessionAuthenticator(stageAuth{})
	ctx := context.Background()
	s, _, err := svc.Create(ctx, CreateInput{UserID: "u", DeviceUID: "d", DeviceModel: "m", Transport: "nfc"}, "mismatch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Discover(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Attest(ctx, s.ID, "response"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(ctx, s.ID, "proof"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.RequestToken(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := svc.ReceiveToken(ctx, TokenWebhook{SessionID: s.ID, TokenReference: "wrong", EventID: "event-2"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if failed.State != domain.StateFailed || failed.FailureCode != "TOKEN_REFERENCE_MISMATCH" {
		t.Fatalf("unexpected failure state: %#v", failed)
	}
}

func TestTokenWebhookRetryIsIdempotent(t *testing.T) {
	repo := memory.NewSessionRepository()
	svc := New(repo, mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	svc.SetSessionAuthenticator(stageAuth{})
	ctx := context.Background()
	s, _, err := svc.Create(ctx, CreateInput{UserID: "u", DeviceUID: "d", DeviceModel: "m", Transport: "nfc"}, "retry")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Discover(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Attest(ctx, s.ID, "response"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(ctx, s.ID, "proof"); err != nil {
		t.Fatal(err)
	}
	requested, err := svc.RequestToken(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	event := TokenWebhook{SessionID: s.ID, TokenReference: requested.TokenReference, EventID: "event-1"}
	first, err := svc.ReceiveToken(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.ReceiveToken(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != second.Version || second.State != domain.StateTokenReceived {
		t.Fatalf("retry changed state/version: %#v %#v", first, second)
	}
}

type expiryTokenPort struct{ calls int }

func (p *expiryTokenPort) RequestToken(context.Context, string, string) (string, error) {
	p.calls++
	return "provider-reference", nil
}

func TestRequestTokenRejectsSessionAtExpiryBeforeProviderCall(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepository()
	expiresAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := domain.ProvisioningSession{ID: "expired-token-request", IdempotencyKey: "expired-token-request-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, CreatedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create session: created=%t err=%v", created, err)
	}
	tokens := &expiryTokenPort{}
	svc := New(repo, nil, tokens, nil)
	svc.now = func() time.Time { return expiresAt }

	got, err := svc.RequestToken(ctx, session.ID)
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("RequestToken error = %v, want ErrSessionExpired", err)
	}
	if tokens.calls != 0 {
		t.Fatalf("provider called %d times for expired session, want 0", tokens.calls)
	}
	if got.State != domain.StateSessionAuthenticated || got.Version != 1 {
		t.Fatalf("expired request mutated session: state=%s version=%d", got.State, got.Version)
	}
}

func TestReceiveTokenRejectsSessionAtExpiry(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepository()
	expiresAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := domain.ProvisioningSession{ID: "expired-token-webhook", IdempotencyKey: "expired-token-webhook-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StateTokenRequested, TokenReference: "provider-reference", Version: 1, CreatedAt: expiresAt.Add(-time.Minute), ExpiresAt: expiresAt}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create session: created=%t err=%v", created, err)
	}
	svc := New(repo, nil, nil, nil)
	svc.now = func() time.Time { return expiresAt }

	got, err := svc.ReceiveToken(ctx, TokenWebhook{SessionID: session.ID, TokenReference: session.TokenReference, EventID: "late-event"})
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("ReceiveToken error = %v, want ErrSessionExpired", err)
	}
	if got.State != domain.StateTokenRequested || got.Version != 1 {
		t.Fatalf("expired callback mutated session: state=%s version=%d", got.State, got.Version)
	}
}

func TestFailRequiresAllowedTransitionAndUnexpiredSession(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	newSession := func(t *testing.T, id string, state domain.ProvisioningState, expiresAt time.Time) (*memory.SessionRepository, *Service, domain.ProvisioningSession) {
		t.Helper()
		repo := memory.NewSessionRepository()
		session := domain.ProvisioningSession{ID: id, IdempotencyKey: id + "-key", UserID: "user", DeviceUID: id + "-device", DeviceModel: "model", Transport: "ble", State: state, Version: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: expiresAt}
		if _, created, err := repo.Create(ctx, session); err != nil || !created {
			t.Fatalf("create %s session: created=%t err=%v", id, created, err)
		}
		svc := New(repo, nil, nil, nil)
		svc.now = func() time.Time { return now }
		return repo, svc, session
	}

	t.Run("valid transition", func(t *testing.T) {
		repo, svc, session := newSession(t, "fail-valid", domain.StateCreated, now.Add(time.Minute))
		failed, err := svc.Fail(ctx, session.ID, "OPERATOR_ABORTED")
		if err != nil || failed.State != domain.StateFailed || failed.FailureCode != "OPERATOR_ABORTED" {
			t.Fatalf("Fail result = state %s code %q err %v", failed.State, failed.FailureCode, err)
		}
		stored, err := repo.Get(ctx, session.ID)
		if err != nil || stored.State != domain.StateFailed {
			t.Fatalf("stored failure state = %s err %v", stored.State, err)
		}
	})

	t.Run("terminal state", func(t *testing.T) {
		repo, svc, session := newSession(t, "fail-terminal", domain.StateCompleted, now.Add(time.Minute))
		got, err := svc.Fail(ctx, session.ID, "OPERATOR_ABORTED")
		if !errors.Is(err, domain.ErrInvalidTransition) {
			t.Fatalf("Fail error = %v, want ErrInvalidTransition", err)
		}
		stored, getErr := repo.Get(ctx, session.ID)
		if getErr != nil || stored.State != domain.StateCompleted || stored.Version != 1 || got.State != domain.StateCompleted {
			t.Fatalf("terminal session changed: result=%+v stored=%+v err=%v", got, stored, getErr)
		}
	})

	t.Run("exact expiry boundary", func(t *testing.T) {
		repo, svc, session := newSession(t, "fail-expired", domain.StateCreated, now)
		got, err := svc.Fail(ctx, session.ID, "OPERATOR_ABORTED")
		if !errors.Is(err, domain.ErrSessionExpired) {
			t.Fatalf("Fail error = %v, want ErrSessionExpired", err)
		}
		stored, getErr := repo.Get(ctx, session.ID)
		if getErr != nil || stored.State != domain.StateCreated || stored.Version != 1 || got.State != domain.StateCreated {
			t.Fatalf("expired session changed: result=%+v stored=%+v err=%v", got, stored, getErr)
		}
	})
}

func TestExternalStageCompletionAfterExpiryDoesNotAdvanceState(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	expiresAt := now.Add(time.Minute)
	t.Run("payload wrapping", func(t *testing.T) {
		repo := memory.NewSessionRepository()
		session := domain.ProvisioningSession{ID: "wrap-expires-during-work", IdempotencyKey: "wrap-expires-during-work-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StateTokenReceived, Version: 1, TokenReference: "provider-reference", CreatedAt: now, ExpiresAt: expiresAt}
		if _, created, err := repo.Create(ctx, session); err != nil || !created {
			t.Fatalf("create session: created=%t err=%v", created, err)
		}
		clock := now
		svc := New(repo, nil, nil, nil)
		svc.now = func() time.Time { return clock }
		svc.SetPayloadWrapper(callbackWrapper(func(context.Context, domain.ProvisioningSession, string) (string, error) {
			clock = expiresAt
			return "wrapped", nil
		}))
		got, err := svc.WrapPayload(ctx, session.ID)
		if !errors.Is(err, domain.ErrSessionExpired) {
			t.Fatalf("WrapPayload error = %v, want ErrSessionExpired", err)
		}
		stored, getErr := repo.Get(ctx, session.ID)
		if getErr != nil || stored.State != domain.StateTokenReceived || stored.Version != 1 || got.State != domain.StateTokenReceived {
			t.Fatalf("expired wrap advanced state: got=%+v stored=%+v err=%v", got, stored, getErr)
		}
	})

	t.Run("APDU transfer", func(t *testing.T) {
		repo := memory.NewSessionRepository()
		session := domain.ProvisioningSession{ID: "transfer-expires-during-work", IdempotencyKey: "transfer-expires-during-work-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StatePayloadWrapped, Version: 1, WrappedPayload: "wrapped", CreatedAt: now, ExpiresAt: expiresAt}
		if _, created, err := repo.Create(ctx, session); err != nil || !created {
			t.Fatalf("create session: created=%t err=%v", created, err)
		}
		clock := now
		svc := New(repo, nil, nil, nil)
		svc.now = func() time.Time { return clock }
		svc.SetAPDUTransport(callbackTransfer(func(context.Context, domain.ProvisioningSession, string) error {
			clock = expiresAt
			return nil
		}))
		got, err := svc.TransferAPDU(ctx, session.ID)
		if !errors.Is(err, domain.ErrSessionExpired) {
			t.Fatalf("TransferAPDU error = %v, want ErrSessionExpired", err)
		}
		stored, getErr := repo.Get(ctx, session.ID)
		if getErr != nil || stored.State != domain.StateTransferStarted || stored.Version != 2 || got.State != domain.StateTransferStarted {
			t.Fatalf("expired transfer advanced beyond started: got=%+v stored=%+v err=%v", got, stored, getErr)
		}
	})
}

type blockingTokenPort struct {
	calls   atomic.Int32
	keys    chan string
	release <-chan struct{}
}

func (p *blockingTokenPort) RequestToken(ctx context.Context, _, key string) (string, error) {
	p.calls.Add(1)
	p.keys <- key
	select {
	case <-p.release:
		return "provider-reference", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestConcurrentTokenRequestsClaimBeforeProviderCall(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepository()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := domain.ProvisioningSession{ID: "concurrent-token-request", IdempotencyKey: "concurrent-token-request-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create session: created=%t err=%v", created, err)
	}
	release := make(chan struct{})
	tokens := &blockingTokenPort{keys: make(chan string, 1), release: release}
	svc := New(repo, nil, tokens, nil)
	svc.now = func() time.Time { return now }

	const callers = 16
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := svc.RequestToken(ctx, session.ID)
			results <- err
		}()
	}
	close(start)
	key := <-tokens.keys
	for range callers - 1 {
		if err := <-results; !errors.Is(err, domain.ErrTokenRequestInProgress) {
			t.Fatalf("concurrent losing request error = %v, want ErrTokenRequestInProgress", err)
		}
	}
	close(release)
	if err := <-results; err != nil {
		t.Fatalf("winning provider request failed: %v", err)
	}
	wg.Wait()
	if got := tokens.calls.Load(); got != 1 {
		t.Fatalf("provider call count = %d, want exactly one", got)
	}
	if key != domain.TokenRequestIdempotencyKey(session.ID) {
		t.Fatalf("provider idempotency key = %q, want stable key %q", key, domain.TokenRequestIdempotencyKey(session.ID))
	}
	stored, err := repo.Get(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != domain.StateTokenRequested || stored.Version != 3 || stored.TokenReference != "provider-reference" {
		t.Fatalf("stored session after winning request = %+v", stored)
	}
}

type ambiguousTimeoutTokenPort struct {
	calls atomic.Int32
	key   string
}

func (p *ambiguousTimeoutTokenPort) RequestToken(_ context.Context, _, key string) (string, error) {
	p.calls.Add(1)
	p.key = key
	return "", errors.New("transport timeout after request dispatch")
}

func TestAmbiguousTokenRequestOutcomeIsDurableAndNotRetried(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepository()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	session := domain.ProvisioningSession{ID: "ambiguous-token-request", IdempotencyKey: "ambiguous-token-request-key", UserID: "user", DeviceUID: "device", DeviceModel: "model", Transport: "ble", State: domain.StateSessionAuthenticated, Version: 1, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, created, err := repo.Create(ctx, session); err != nil || !created {
		t.Fatalf("create session: created=%t err=%v", created, err)
	}
	tokens := &ambiguousTimeoutTokenPort{}
	svc := New(repo, nil, tokens, nil)
	svc.now = func() time.Time { return now }
	first, err := svc.RequestToken(ctx, session.ID)
	if !errors.Is(err, domain.ErrTokenRequestOutcomeUnknown) {
		t.Fatalf("first request error = %v, want ErrTokenRequestOutcomeUnknown", err)
	}
	if first.State != domain.StateTokenRequesting {
		t.Fatalf("ambiguous operation state = %s, want TOKEN_REQUESTING", first.State)
	}
	if tokens.key != domain.TokenRequestIdempotencyKey(session.ID) {
		t.Fatalf("provider operation key = %q, want stable key", tokens.key)
	}
	// Simulate a caller retry after the original service process has returned.
	second, err := svc.RequestToken(ctx, session.ID)
	if !errors.Is(err, domain.ErrTokenRequestOutcomeUnknown) {
		t.Fatalf("retry error = %v, want ErrTokenRequestOutcomeUnknown", err)
	}
	if tokens.calls.Load() != 1 {
		t.Fatalf("provider was called %d times after ambiguous timeout, want 1", tokens.calls.Load())
	}
	claim, err := repo.ClaimTokenRequest(ctx, session.ID, now)
	if err != nil || claim.Operation.Status != domain.TokenRequestUnknown || claim.Claimed {
		t.Fatalf("persisted ambiguous claim = %+v err=%v", claim, err)
	}
	if second.State != domain.StateTokenRequesting {
		t.Fatalf("retry changed session state to %s", second.State)
	}
	// A verified provider callback can reconcile the unknown operation without
	// issuing another provider request.
	reconciled, err := svc.ReceiveToken(ctx, TokenWebhook{SessionID: session.ID, TokenReference: "resolved-provider-reference", EventID: "resolved-event"})
	if err != nil || reconciled.State != domain.StateTokenReceived {
		t.Fatalf("callback reconciliation: state=%s err=%v", reconciled.State, err)
	}
	if tokens.calls.Load() != 1 {
		t.Fatalf("webhook reconciliation retried provider request %d times", tokens.calls.Load())
	}
}
