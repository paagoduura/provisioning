package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/domain"
)

type transitioner struct {
	sessions map[string]domain.ProvisioningSession
}

func (t *transitioner) Get(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	s, ok := t.sessions[id]
	if !ok {
		return domain.ProvisioningSession{}, ErrChallengeNotFound
	}
	return s, nil
}
func (t *transitioner) TransitionToAttested(ctx context.Context, id string) (domain.ProvisioningSession, error) {
	s := t.sessions[id]
	if err := s.Transition(domain.StateDeviceAttested); err != nil {
		return s, err
	}
	t.sessions[id] = s
	return s, nil
}

type testRepo struct {
	challenges map[string]Challenge
	records    []VerifiedResult
}

func (r *testRepo) Create(ctx context.Context, c Challenge) error {
	if r.challenges == nil {
		r.challenges = map[string]Challenge{}
	}
	r.challenges[c.ID] = c
	return nil
}
func (r *testRepo) Get(ctx context.Context, id string) (Challenge, error) {
	c, ok := r.challenges[id]
	if !ok {
		return Challenge{}, ErrChallengeNotFound
	}
	return c, nil
}
func (r *testRepo) Consume(ctx context.Context, id string, now time.Time) (Challenge, error) {
	c, ok := r.challenges[id]
	if !ok {
		return Challenge{}, ErrChallengeNotFound
	}
	if c.UsedAt != nil {
		return Challenge{}, ErrChallengeUsed
	}
	if !now.Before(c.ExpiresAt) {
		return Challenge{}, ErrChallengeExpired
	}
	used := now
	c.UsedAt = &used
	r.challenges[id] = c
	return c, nil
}
func (r *testRepo) SaveAttestation(ctx context.Context, sessionID string, result VerifiedResult, now time.Time) error {
	r.records = append(r.records, result)
	return nil
}
func (r *testRepo) LatestCounter(ctx context.Context, sessionID, provider, keyID string) (uint64, bool, error) {
	for i := len(r.records) - 1; i >= 0; i-- {
		if r.records[i].Provider == provider && r.records[i].KeyID == keyID {
			return r.records[i].Counter, true, nil
		}
	}
	return 0, false, nil
}

func TestChallengeIsBoundAndSingleUse(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	public := private.Public().(ed25519.PublicKey)
	repo := &testRepo{}
	tr := &transitioner{sessions: map[string]domain.ProvisioningSession{"s1": {ID: "s1", State: domain.StateDeviceDiscovered, ExpiresAt: now().Add(10 * time.Minute)}}}
	svc := New(repo, repo, DevEd25519Verifier{Keys: map[string]ed25519.PublicKey{"k1": public}}, tr, nil)
	challenge, err := svc.IssueChallenge(context.Background(), "s1", "request-digest")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte(challenge.Value + "\nrequest-digest\ns1")
	assertion := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	result, err := svc.Verify(context.Background(), "s1", Submission{ChallengeID: challenge.ID, Provider: "dev-ed25519", KeyID: "k1", Assertion: assertion, RequestHash: "request-digest"})
	if err != nil {
		t.Fatal(err)
	}
	if result.TrustLevel != "development" {
		t.Fatalf("unexpected trust level: %s", result.TrustLevel)
	}
	if _, err := svc.Verify(context.Background(), "s1", Submission{ChallengeID: challenge.ID, Provider: "dev-ed25519", KeyID: "k1", Assertion: assertion, RequestHash: "request-digest"}); err != ErrChallengeUsed {
		t.Fatalf("expected one-time challenge rejection, got %v", err)
	}
}

func now() time.Time { return time.Now() }
