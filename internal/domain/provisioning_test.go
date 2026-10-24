package domain

import (
	"strings"
	"testing"
)

func TestProvisioningSessionAllowsOnlyDeclaredTransitions(t *testing.T) {
	s := ProvisioningSession{State: StateCreated}
	if err := s.Transition(StateDeviceDiscovered); err != nil {
		t.Fatalf("expected valid transition: %v", err)
	}
	if err := s.Transition(StateCompleted); err == nil {
		t.Fatal("expected invalid transition")
	} else if !strings.Contains(err.Error(), "invalid provisioning state transition") {
		t.Fatalf("unexpected error: %v", err)
	}
}
