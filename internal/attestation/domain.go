package attestation

import (
	"context"
	"time"
)

type Challenge struct {
	ID              string
	SessionID       string
	Value           string
	RequestHash     string // server-generated digest; retained as the database-compatible field name
	RequestDocument []byte
	ExpiresAt       time.Time
	UsedAt          *time.Time
}

type Submission struct {
	ChallengeID string `json:"challenge_id"`
	Provider    string `json:"provider"`
	KeyID       string `json:"key_id"`
	Assertion   string `json:"assertion"`
	RequestHash string `json:"-"` // populated only by the server from the challenge
}

type VerifiedResult struct {
	Provider      string `json:"provider"`
	KeyID         string `json:"key_id"`
	Counter       uint64 `json:"counter"`
	TrustLevel    string `json:"trust_level"`
	PublicKeyDER  []byte `json:"-"`
	BundleVersion string `json:"-"`
	Environment   string `json:"-"`
}

type Verifier interface {
	Verify(context.Context, Challenge, Submission) (VerifiedResult, error)
}
