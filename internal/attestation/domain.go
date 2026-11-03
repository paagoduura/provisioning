package attestation

import (
	"context"
	"time"
)

type Challenge struct {
	ID          string
	SessionID   string
	Value       string
	RequestHash string
	ExpiresAt   time.Time
	UsedAt      *time.Time
}

type Submission struct {
	ChallengeID string `json:"challenge_id"`
	Provider    string `json:"provider"`
	KeyID       string `json:"key_id"`
	Assertion   string `json:"assertion"`
	RequestHash string `json:"request_hash"`
}

type VerifiedResult struct {
	Provider   string `json:"provider"`
	KeyID      string `json:"key_id"`
	Counter    uint64 `json:"counter"`
	TrustLevel string `json:"trust_level"`
}

type Verifier interface {
	Verify(context.Context, Challenge, Submission) (VerifiedResult, error)
}
