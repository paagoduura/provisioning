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
	RequestHashDigest []byte
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
	Provider   string
	KeyID      string
	Counter    uint64
	TrustLevel string
}

type Verifier interface {
	Verify(context.Context, Challenge, Submission) (VerifiedResult, error)
}
