package readiness

import (
	"context"
	"errors"
	"testing"
)

func TestCheckerFailsWhenRequiredCheckFails(t *testing.T) {
	report := New(
		Check{Name: "database", Required: true, Run: func(context.Context) error { return errors.New("unavailable") }},
		Check{Name: "optional_provider", Required: false, Run: func(context.Context) error { return errors.New("not configured") }},
	).Check(context.Background())
	if report.Status != "not_ready" {
		t.Fatalf("status = %q, want not_ready", report.Status)
	}
	if report.Checks["database"].Status != "failed" || report.Checks["optional_provider"].Status != "failed" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
}

func TestCheckerIsReadyWhenOnlyOptionalCheckFails(t *testing.T) {
	report := New(
		Check{Name: "database", Required: true, Run: func(context.Context) error { return nil }},
		Check{Name: "optional_provider", Required: false, Run: func(context.Context) error { return errors.New("not configured") }},
	).Check(context.Background())
	if report.Status != "ok" {
		t.Fatalf("status = %q, want ok", report.Status)
	}
	if report.Checks["database"].Status != "ok" || report.Checks["optional_provider"].Status != "failed" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
}
