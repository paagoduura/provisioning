package attestation

import (
	"context"
	"time"
)

const (
	BindingScopeDeviceKey = "device_key"
	BindingScopeSession   = "session"
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
	KeyID         string `json:"key_id,omitempty"`
	Counter       uint64 `json:"counter,omitempty"`
	TrustLevel    string `json:"trust_level"`
	BindingScope  string `json:"binding_scope"`
	PublicKeyDER  []byte `json:"-"`
	BundleVersion string `json:"-"`
	Environment   string `json:"-"`
}

type Verifier interface {
	Verify(context.Context, Challenge, Submission) (VerifiedResult, error)
}
