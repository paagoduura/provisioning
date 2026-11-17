package retention

import (
	"testing"
	"time"
)

func TestPolicyRequiresExplicitPositiveWindows(t *testing.T) {
	var policy Policy
	if err := policy.Validate(); err == nil {
		t.Fatal("zero-value retention policy unexpectedly accepted")
	}
	policy = Policy{
		ExpiredChallengeAge: time.Hour,
		ExpiredSessionAge:   time.Hour,
		WebhookEventAge:     time.Hour,
		AuditEventAge:       time.Hour,
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid explicit policy rejected: %v", err)
	}
	policy.AuditEventAge = -time.Second
	if err := policy.Validate(); err == nil {
		t.Fatal("negative audit retention unexpectedly accepted")
	}
}

func TestLimitsAreHardBounded(t *testing.T) {
	for _, size := range []int{0, -1, 1001} {
		if err := (Limits{BatchSize: size}).Validate(); err == nil {
			t.Errorf("batch size %d unexpectedly accepted", size)
		}
	}
	if err := (Limits{BatchSize: 1}).Validate(); err != nil {
		t.Fatalf("minimum batch size rejected: %v", err)
	}
	if err := (Limits{BatchSize: 1000}).Validate(); err != nil {
		t.Fatalf("maximum batch size rejected: %v", err)
	}
}
