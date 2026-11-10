package attestation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/audit"
	"github.com/paagoduura/provisioning/internal/domain"
)

var (
	ErrChallengeNotFound   = errors.New("attestation challenge not found")
	ErrChallengeExpired    = errors.New("attestation challenge expired")
	ErrChallengeUsed       = errors.New("attestation challenge already used")
	ErrRequestBinding      = errors.New("attestation request binding mismatch")
	ErrUnsupportedProvider = errors.New("attestation provider is not configured")
	ErrCounterRollback     = errors.New("attestation counter did not increase")
	ErrDeviceRevoked       = errors.New("attestation device key is revoked")
)

type ChallengeRepository interface {
	Create(context.Context, Challenge) error
	Get(context.Context, string) (Challenge, error)
	Consume(context.Context, string, time.Time) (Challenge, error)
}

type AttestationRecordRepository interface {
	// SaveAttestationIfCounterAdvances atomically persists a result only when
	// its counter is greater than the currently stored counter for this key.
	SaveAttestationIfCounterAdvances(context.Context, string, VerifiedResult, time.Time) (bool, error)
}

type RevocationChecker interface {
	IsRevoked(context.Context, string, string) (bool, error)
}

type Service struct {
	challenges   ChallengeRepository
	records      AttestationRecordRepository
	verifier     Verifier
	transitioner interface {
		Get(context.Context, string) (domain.ProvisioningSession, error)
		TransitionToAttested(context.Context, string) (domain.ProvisioningSession, error)
	}
	audit       audit.Sink
	now         func() time.Time
	revocations RevocationChecker
}

func New(challenges ChallengeRepository, records AttestationRecordRepository, verifier Verifier, transitioner interface {
	Get(context.Context, string) (domain.ProvisioningSession, error)
	TransitionToAttested(context.Context, string) (domain.ProvisioningSession, error)
}, auditSink audit.Sink) *Service {
	return &Service{challenges: challenges, records: records, verifier: verifier, transitioner: transitioner, audit: auditSink, now: time.Now}
}

func (s *Service) SetRevocationChecker(checker RevocationChecker) { s.revocations = checker }

func (s *Service) IssueChallenge(ctx context.Context, sessionID, requestHash string) (challenge Challenge, err error) {
	defer func() {
		if err != nil && s.audit != nil {
			_ = s.audit.Record(ctx, audit.Event{SessionID: sessionID, Type: "ATTESTATION_CHALLENGE_FAILED", Result: "FAILURE", Reason: FailureCode(err), At: s.now()})
		}
	}()
	if strings.TrimSpace(sessionID) == "" {
		return Challenge{}, errors.New("session id is required")
	}
	if len(requestHash) > 500 {
		return Challenge{}, errors.New("request hash exceeds 500 bytes")
	}
	session, err := s.transitioner.Get(ctx, sessionID)
	if err != nil {
		return Challenge{}, err
	}
	if session.Expired(s.now()) {
		return Challenge{}, errors.New("session expired")
	}
	if session.State != domain.StateDeviceDiscovered {
		return Challenge{}, errors.New("device must be discovered before attestation")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Challenge{}, err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	idRaw := make([]byte, 16)
	if _, err := rand.Read(idRaw); err != nil {
		return Challenge{}, err
	}
	challenge = Challenge{ID: "att_" + base64.RawURLEncoding.EncodeToString(idRaw), SessionID: sessionID, Value: value, RequestHash: requestHash, ExpiresAt: s.now().Add(5 * time.Minute)}
	if err := s.challenges.Create(ctx, challenge); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (s *Service) Verify(ctx context.Context, sessionID string, input Submission) (result VerifiedResult, err error) {
	defer func() {
		if err != nil && s.audit != nil {
			_ = s.audit.Record(ctx, audit.Event{SessionID: sessionID, Type: "DEVICE_ATTESTATION_FAILED", Result: "FAILURE", Reason: FailureCode(err), At: s.now()})
		}
	}()
	if input.Provider == "" || input.KeyID == "" || input.Assertion == "" || input.RequestHash == "" {
		return VerifiedResult{}, errors.New("provider, key_id and assertion are required")
	}
	if input.ChallengeID == "" {
		return VerifiedResult{}, errors.New("challenge_id is required")
	}
	challenge, err := s.challenges.Get(ctx, input.ChallengeID)
	if err != nil {
		return VerifiedResult{}, err
	}
	if challenge.UsedAt != nil {
		return VerifiedResult{}, ErrChallengeUsed
	}
	if !s.now().Before(challenge.ExpiresAt) {
		return VerifiedResult{}, ErrChallengeExpired
	}
	if challenge.SessionID != sessionID {
		return VerifiedResult{}, ErrRequestBinding
	}
	if challenge.RequestHash != input.RequestHash {
		return VerifiedResult{}, ErrRequestBinding
	}
	if s.revocations != nil {
		revoked, checkErr := s.revocations.IsRevoked(ctx, input.Provider, input.KeyID)
		if checkErr != nil {
			return VerifiedResult{}, checkErr
		}
		if revoked {
			return VerifiedResult{}, ErrDeviceRevoked
		}
	}
	if s.verifier == nil {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	result, err = s.verifier.Verify(ctx, challenge, input)
	if err != nil {
		return VerifiedResult{}, err
	}
	if result.Provider != input.Provider || result.KeyID != input.KeyID || result.TrustLevel == "" {
		return VerifiedResult{}, errors.New("invalid verifier result")
	}
	if _, err := s.challenges.Consume(ctx, input.ChallengeID, s.now()); err != nil {
		return VerifiedResult{}, err
	}
	advanced, err := s.records.SaveAttestationIfCounterAdvances(ctx, sessionID, result, s.now())
	if err != nil {
		return VerifiedResult{}, err
	}
	if !advanced {
		return VerifiedResult{}, ErrCounterRollback
	}
	if _, err := s.transitioner.TransitionToAttested(ctx, sessionID); err != nil {
		return VerifiedResult{}, err
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, audit.Event{SessionID: sessionID, Type: "DEVICE_ATTESTED", Result: "SUCCESS", At: s.now()})
	}
	return result, nil
}

func hashRequest(value string) []byte   { sum := sha256.Sum256([]byte(value)); return sum[:] }
func challengeHash(value string) []byte { sum := sha256.Sum256([]byte(value)); return sum[:] }
