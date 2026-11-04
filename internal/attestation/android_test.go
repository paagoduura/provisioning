package attestation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type fakePlayIntegrityDecoder struct {
	payload PlayIntegrityPayload
	err     error
}

func (f fakePlayIntegrityDecoder) Decode(context.Context, string) (PlayIntegrityPayload, error) {
	return f.payload, f.err
}

type staticTokenSource struct{}

func (staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "access-token"}, nil
}

func validAndroidVerifier(payload PlayIntegrityPayload) AndroidPlayIntegrityVerifier {
	return AndroidPlayIntegrityVerifier{
		PackageName:           "com.example.provisioning",
		CloudProjectNumber:    123456789,
		Mode:                  PlayIntegrityStandard,
		MaxTokenAge:           2 * time.Minute,
		ClockSkew:             time.Second,
		RequireLicensed:       true,
		AllowedDeviceVerdicts: map[string]struct{}{"MEETS_DEVICE_INTEGRITY": {}},
		Decoder:               fakePlayIntegrityDecoder{payload: payload},
		Now:                   func() time.Time { return time.UnixMilli(1_700_000_060_000) },
	}
}

func validAndroidPayload() PlayIntegrityPayload {
	return PlayIntegrityPayload{
		RequestDetails: PlayIntegrityRequestDetails{
			RequestPackageName: "com.example.provisioning",
			RequestHash:        "request-hash",
			TimestampMillis:    FlexibleUint64(1_700_000_000_000),
		},
		AppIntegrity: PlayIntegrityAppIntegrity{
			AppRecognitionVerdict: "PLAY_RECOGNIZED",
			PackageName:           "com.example.provisioning",
		},
		DeviceIntegrity: PlayIntegrityDeviceIntegrity{DeviceRecognitionVerdict: []string{"MEETS_DEVICE_INTEGRITY"}},
		AccountDetails:  PlayIntegrityAccountDetails{AppLicensingVerdict: "LICENSED"},
	}
}

func TestAndroidPlayIntegrityVerifierVerifiesStandardPayload(t *testing.T) {
	verifier := validAndroidVerifier(validAndroidPayload())
	result, err := verifier.Verify(context.Background(), Challenge{Value: "challenge"}, Submission{
		Provider:    AndroidPlayIntegrityProvider,
		KeyID:       "android-device-1",
		Assertion:   "opaque-google-token",
		RequestHash: "request-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Provider != AndroidPlayIntegrityProvider || result.KeyID != "android-device-1" || result.TrustLevel != "android-play-integrity-verified" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Counter != 1_700_000_000_000 {
		t.Fatalf("unexpected token timestamp counter: %d", result.Counter)
	}
}

func TestAndroidPlayIntegrityVerifierRejectsRequestMismatch(t *testing.T) {
	verifier := validAndroidVerifier(validAndroidPayload())
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:    AndroidPlayIntegrityProvider,
		KeyID:       "device",
		Assertion:   "token",
		RequestHash: "different-request",
	})
	if !errors.Is(err, ErrAndroidRequestMismatch) {
		t.Fatalf("expected request mismatch, got %v", err)
	}
}

func TestAndroidPlayIntegrityVerifierRejectsPackageVerdictAndLicense(t *testing.T) {
	payload := validAndroidPayload()
	payload.RequestDetails.RequestPackageName = "com.attacker.app"
	verifier := validAndroidVerifier(payload)
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{Provider: AndroidPlayIntegrityProvider, KeyID: "device", Assertion: "token", RequestHash: "request-hash"})
	if !errors.Is(err, ErrAndroidPackageMismatch) {
		t.Fatalf("expected package mismatch, got %v", err)
	}

	payload = validAndroidPayload()
	payload.AccountDetails.AppLicensingVerdict = "UNLICENSED"
	verifier = validAndroidVerifier(payload)
	_, err = verifier.Verify(context.Background(), Challenge{}, Submission{Provider: AndroidPlayIntegrityProvider, KeyID: "device", Assertion: "token", RequestHash: "request-hash"})
	if !errors.Is(err, ErrAndroidAccountUnlicensed) {
		t.Fatalf("expected unlicensed failure, got %v", err)
	}
}

func TestAndroidPlayIntegrityVerifierRejectsStaleAndWeakDevice(t *testing.T) {
	payload := validAndroidPayload()
	payload.RequestDetails.TimestampMillis = FlexibleUint64(1_699_999_000_000)
	verifier := validAndroidVerifier(payload)
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{Provider: AndroidPlayIntegrityProvider, KeyID: "device", Assertion: "token", RequestHash: "request-hash"})
	if !errors.Is(err, ErrAndroidTokenExpired) {
		t.Fatalf("expected stale token failure, got %v", err)
	}

	payload = validAndroidPayload()
	payload.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_BASIC_INTEGRITY"}
	verifier = validAndroidVerifier(payload)
	_, err = verifier.Verify(context.Background(), Challenge{}, Submission{Provider: AndroidPlayIntegrityProvider, KeyID: "device", Assertion: "token", RequestHash: "request-hash"})
	if !errors.Is(err, ErrAndroidDeviceIntegrity) {
		t.Fatalf("expected device integrity failure, got %v", err)
	}
}

func TestAndroidPlayIntegrityVerifierSupportsClassicNonce(t *testing.T) {
	payload := validAndroidPayload()
	payload.RequestDetails.RequestHash = ""
	payload.RequestDetails.Nonce = "challenge"
	verifier := validAndroidVerifier(payload)
	verifier.Mode = PlayIntegrityClassic
	result, err := verifier.Verify(context.Background(), Challenge{Value: "challenge"}, Submission{
		Provider:  AndroidPlayIntegrityProvider,
		KeyID:     "device",
		Assertion: "token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TrustLevel != "android-play-integrity-verified" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestGooglePlayIntegrityClientDecodesAuthenticatedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("unexpected request: %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"integrity_token":"opaque-token"`) {
			t.Fatalf("unexpected request body: %s", body)
		}
		_, _ = w.Write([]byte(`{"tokenPayloadExternal":"{\"requestDetails\":{\"requestPackageName\":\"com.example.provisioning\",\"requestHash\":\"request-hash\",\"timestampMillis\":\"1700000000000\"},\"appIntegrity\":{\"appRecognitionVerdict\":\"PLAY_RECOGNIZED\",\"packageName\":\"com.example.provisioning\"},\"deviceIntegrity\":{\"deviceRecognitionVerdict\":[\"MEETS_DEVICE_INTEGRITY\"]},\"accountDetails\":{\"appLicensingVerdict\":\"LICENSED\"}}"}`))
	}))
	defer server.Close()
	client := GooglePlayIntegrityClient{PackageName: "com.example.provisioning", Endpoint: server.URL, TokenSource: staticTokenSource{}}
	payload, err := client.Decode(context.Background(), "opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	if payload.RequestDetails.RequestHash != "request-hash" || payload.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestFlexibleUint64AcceptsStringAndNumber(t *testing.T) {
	var stringValue FlexibleUint64
	if err := stringValue.UnmarshalJSON([]byte(`"42"`)); err != nil || stringValue != 42 {
		t.Fatalf("string timestamp parse failed: %v %d", err, stringValue)
	}
	var numericValue FlexibleUint64
	if err := numericValue.UnmarshalJSON([]byte(`42`)); err != nil || numericValue != 42 {
		t.Fatalf("numeric timestamp parse failed: %v %d", err, numericValue)
	}
}
