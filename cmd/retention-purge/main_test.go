package main

import (
	"testing"
)

func TestPolicyFromEnvRequiresEveryExplicitWindow(t *testing.T) {
	for _, name := range []string{
		"RETENTION_EXPIRED_CHALLENGE_AGE",
		"RETENTION_EXPIRED_SESSION_AGE",
		"RETENTION_WEBHOOK_EVENT_AGE",
		"RETENTION_AUDIT_EVENT_AGE",
	} {
		t.Run(name, func(t *testing.T) {
			setPolicyEnv(t)
			t.Setenv(name, "")
			if _, err := policyFromEnv(); err == nil {
				t.Fatalf("missing %s unexpectedly accepted", name)
			}
		})
	}
}

func TestPolicyFromEnvRejectsInvalidDuration(t *testing.T) {
	for _, value := range []string{"abc", "0s", "-1h"} {
		t.Run(value, func(t *testing.T) {
			setPolicyEnv(t)
			t.Setenv("RETENTION_WEBHOOK_EVENT_AGE", value)
			if _, err := policyFromEnv(); err == nil {
				t.Fatalf("duration %q unexpectedly accepted", value)
			}
		})
	}
}

func TestPolicyFromEnvAcceptsAllExplicitWindows(t *testing.T) {
	setPolicyEnv(t)
	policy, err := policyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if policy.ExpiredChallengeAge.String() != "72h0m0s" || policy.ExpiredSessionAge.String() != "168h0m0s" || policy.WebhookEventAge.String() != "240h0m0s" || policy.AuditEventAge.String() != "720h0m0s" {
		t.Fatalf("unexpected parsed policy: %+v", policy)
	}
}

func setPolicyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RETENTION_EXPIRED_CHALLENGE_AGE", "72h")
	t.Setenv("RETENTION_EXPIRED_SESSION_AGE", "168h")
	t.Setenv("RETENTION_WEBHOOK_EVENT_AGE", "240h")
	t.Setenv("RETENTION_AUDIT_EVENT_AGE", "720h")
}
