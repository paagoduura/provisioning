package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/audit"
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
	revoked    map[string]bool
}

func (r *testRepo) Create(ctx context.Context, c Challenge) error {
	if r.challenges == nil {
		r.challenges = map[string]Challenge{}
	}
	if r.revoked == nil {
		r.revoked = map[string]bool{}
	}
	r.challenges[c.ID] = c
	return nil
}
func (r *testRepo) IsRevoked(ctx context.Context, provider, keyID string) (bool, error) {
	return r.revoked[provider+"\x00"+keyID], nil
}
func (r *testRepo) Revoke(provider, keyID string) {
	if r.revoked == nil {
		r.revoked = map[string]bool{}
	}
	r.revoked[provider+"\x00"+keyID] = true
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
func (r *testRepo) SaveAttestationIfCounterAdvances(ctx context.Context, sessionID string, result VerifiedResult, now time.Time) (bool, error) {
	for i := len(r.records) - 1; i >= 0; i-- {
		if r.records[i].Provider == result.Provider && r.records[i].KeyID == result.KeyID {
			if result.Counter <= r.records[i].Counter {
				return false, nil
			}
			break
		}
	}
	r.records = append(r.records, result)
	return true, nil
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

func TestAlteredClonedAndRevokedDevicesFail(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	public := private.Public().(ed25519.PublicKey)
	repo := &testRepo{}
	tr := &transitioner{sessions: map[string]domain.ProvisioningSession{
		"s1": {ID: "s1", State: domain.StateDeviceDiscovered, ExpiresAt: now().Add(10 * time.Minute)},
		"s2": {ID: "s2", State: domain.StateDeviceDiscovered, ExpiresAt: now().Add(10 * time.Minute)},
	}}
	svc := New(repo, repo, DevEd25519Verifier{Keys: map[string]ed25519.PublicKey{"k1": public}}, tr, nil)
	svc.SetRevocationChecker(repo)
	altered, err := svc.IssueChallenge(context.Background(), "s1", "request-digest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Verify(context.Background(), "s1", Submission{ChallengeID: altered.ID, Provider: "dev-ed25519", KeyID: "k1", Assertion: base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)), RequestHash: "request-digest"}); err == nil {
		t.Fatal("altered signature unexpectedly passed")
	}
	if _, err = svc.Verify(context.Background(), "s1", Submission{ChallengeID: altered.ID, Provider: "dev-ed25519", KeyID: "clone-key", Assertion: "fake", RequestHash: "request-digest"}); err == nil {
		t.Fatal("cloned or unknown key unexpectedly passed")
	}
	valid, err := svc.IssueChallenge(context.Background(), "s2", "request-digest")
	if err != nil {
		t.Fatal(err)
	}
	repo.Revoke("dev-ed25519", "k1")
	message := []byte(valid.Value + "\nrequest-digest\ns2")
	assertion := base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	if _, err = svc.Verify(context.Background(), "s2", Submission{ChallengeID: valid.ID, Provider: "dev-ed25519", KeyID: "k1", Assertion: assertion, RequestHash: "request-digest"}); err != ErrDeviceRevoked {
		t.Fatalf("expected revoked-device failure, got %v", err)
	}
}

func TestFailureAuditIsRedactedAndMapped(t *testing.T) {
	repo := &testRepo{}
	tr := &transitioner{sessions: map[string]domain.ProvisioningSession{"s1": {ID: "s1", State: domain.StateDeviceDiscovered, ExpiresAt: now().Add(10 * time.Minute)}}}
	sink := audit.NewMemorySink()
	svc := New(repo, repo, UnavailableVerifier{}, tr, sink)
	challenge, err := svc.IssueChallenge(context.Background(), "s1", "request-digest")
	if err != nil {
		t.Fatal(err)
	}
	secret := "opaque-device-signature-must-not-be-audit-reason"
	_, err = svc.Verify(context.Background(), "s1", Submission{ChallengeID: challenge.ID, Provider: "apple-app-attest", KeyID: "key", Assertion: secret, RequestHash: "request-digest"})
	if err != ErrUnsupportedProvider {
		t.Fatalf("expected unsupported provider, got %v", err)
	}
	events := sink.Events()
	if len(events) != 1 || events[0].Reason != FailureProviderUnavailable {
		t.Fatalf("unexpected audit events: %+v", events)
	}
	if events[0].Reason == secret {
		t.Fatal("raw assertion was written to the audit reason")
	}
}

func now() time.Time { return time.Now() }
