package retention

import (
	"errors"
	"time"
)

// Policy contains operator-approved retention windows. Each duration is the
// minimum age after its respective event/expiry timestamp before deletion.
// The application intentionally defines no defaults: callers must supply the
// approved legal, contractual, and operational policy explicitly.
type Policy struct {
	ExpiredChallengeAge time.Duration
	ExpiredSessionAge   time.Duration
	WebhookEventAge     time.Duration
	AuditEventAge       time.Duration
}

// Limits bounds each purge category independently for one invocation.
type Limits struct {
	BatchSize int
}

func (p Policy) Validate() error {
	if p.ExpiredChallengeAge <= 0 {
		return errors.New("expired challenge retention must be a positive duration")
	}
	if p.ExpiredSessionAge <= 0 {
		return errors.New("expired session retention must be a positive duration")
	}
	if p.WebhookEventAge <= 0 {
		return errors.New("webhook event retention must be a positive duration")
	}
	if p.AuditEventAge <= 0 {
		return errors.New("audit event retention must be a positive duration")
	}
	return nil
}

func (l Limits) Validate() error {
	if l.BatchSize < 1 || l.BatchSize > 1000 {
		return errors.New("purge batch size must be between 1 and 1000")
	}
	return nil
}
