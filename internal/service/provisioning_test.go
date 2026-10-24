package service

import (
	"context"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
)

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
