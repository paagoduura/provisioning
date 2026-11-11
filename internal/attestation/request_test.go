package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/paagoduura/provisioning/internal/domain"
)

func TestCanonicalProvisioningRequestIsDeterministicAndChallengeBound(t *testing.T) {
	session := domain.ProvisioningSession{ID: "session-1", DeviceID: "dev-1", DeviceModel: "wearable-v1", Transport: "ble"}
	request, document, digest, err := buildCanonicalProvisioningRequest(session, "challenge-1")
	if err != nil {
		t.Fatal(err)
	}
	if request.Operation != "provision" || request.Version != 1 {
		t.Fatalf("unexpected canonical request metadata: %+v", request)
	}
	wantDocument := `{"device_id":"dev-1","device_model":"wearable-v1","operation":"provision","session_id":"session-1","transport":"ble","version":1}`
	if string(document) != wantDocument {
		t.Fatalf("canonical document = %s, want %s", document, wantDocument)
	}
	input := append(append([]byte("provisioning-request-v1\n"), document...), []byte("\nchallenge=challenge-1")...)
	sum := sha256.Sum256(input)
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != digest {
		t.Fatalf("digest = %s, want %s", digest, got)
	}
	_, _, otherDigest, err := buildCanonicalProvisioningRequest(session, "challenge-2")
	if err != nil {
		t.Fatal(err)
	}
	if otherDigest == digest {
		t.Fatal("different one-time challenges produced the same request digest")
	}
}
