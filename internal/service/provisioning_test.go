package service

import (
	"context"
	"errors"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/domain"
)

type testPersonalizer struct{ transfers, verifications int }

func (p *testPersonalizer) Transfer(context.Context, string, string) error {
	p.transfers++
	return nil
}

func (p *testPersonalizer) Verify(context.Context, string, string) error {
	p.verifications++
	return nil
}

func TestCreateIsIdempotent(t *testing.T) {
	svc := New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	input := CreateInput{UserID: "u-1", DeviceUID: "d-1", DeviceModel: "wearable-v1", Transport: "ble"}
	first, replay, err := svc.Create(context.Background(), input, "idem-1")
	if err != nil || replay {
		t.Fatalf("unexpected first result: replay=%v err=%v", replay, err)
	}
	second, replay, err := svc.Create(context.Background(), input, "idem-1")
	if err != nil || !replay {
		t.Fatalf("unexpected replay result: replay=%v err=%v", replay, err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected same session ID, got %s and %s", first.ID, second.ID)
	}
}

func TestCreateRequiresIdempotencyKey(t *testing.T) {
	svc := New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	_, _, err := svc.Create(context.Background(), CreateInput{UserID: "u-1"}, "")
	if err == nil {
		t.Fatal("expected missing idempotency key error")
	}
}

func TestPaymentProvisioningCompletesAndPersistsReferences(t *testing.T) {
	svc := New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	personalizer := &testPersonalizer{}
	svc.SetPersonalizer(personalizer)
	session, _, err := svc.Create(context.Background(), CreateInput{UserID: "u-1", DeviceUID: "d-1", DeviceModel: "wearable-v1", Transport: "nfc"}, "idem-payment-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Discover(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TransitionToAttested(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateSession(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	result, err := svc.ProvisionPayment(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != domain.StateCompleted || result.PaymentTokenRef == "" || result.WrappedPayloadRef == "" {
		t.Fatalf("unexpected completed session: %+v", result)
	}
	if personalizer.transfers != 1 || personalizer.verifications != 1 {
		t.Fatalf("unexpected personalizer calls: %+v", personalizer)
	}
	replay, err := svc.ProvisionPayment(context.Background(), session.ID)
	if err != nil || replay.State != domain.StateCompleted {
		t.Fatalf("expected idempotent completed replay, state=%s err=%v", replay.State, err)
	}
	if personalizer.transfers != 1 || personalizer.verifications != 1 {
		t.Fatal("completed replay repeated secure-element operations")
	}
}

func TestPaymentProvisioningFailsClosedWithoutPersonalizer(t *testing.T) {
	svc := New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	session, _, err := svc.Create(context.Background(), CreateInput{UserID: "u-1", DeviceUID: "d-1", DeviceModel: "wearable-v1", Transport: "nfc"}, "idem-payment-2")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = svc.Discover(context.Background(), session.ID)
	_, _ = svc.TransitionToAttested(context.Background(), session.ID)
	_, _ = svc.AuthenticateSession(context.Background(), session.ID)
	result, err := svc.ProvisionPayment(context.Background(), session.ID)
	if err == nil || !errors.Is(err, ErrPaymentIntegrationNotConfigured) {
		t.Fatalf("expected payment integration failure, got %v", err)
	}
	if result.State != domain.StateFailed || result.FailureCode != "PAYMENT_INTEGRATION_NOT_CONFIGURED" {
		t.Fatalf("unexpected failure state: %+v", result)
	}
}
