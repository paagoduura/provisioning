package service

import (
	"context"
	"testing"

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

type stageTransfer struct{}

func (stageTransfer) Transfer(context.Context, domain.ProvisioningSession, string) error { return nil }

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
