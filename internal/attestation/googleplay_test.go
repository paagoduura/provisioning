package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type staticTokenSource struct{}

func (staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "test-access-token"}, nil
}

func googleAssertion(t *testing.T, token string) string {
	t.Helper()
	data, err := json.Marshal(googlePlayAssertion{IntegrityToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func googleVerdictJSON(requestHash, packageName string) string {
	return `{"tokenPayloadExternal":{"requestDetails":{"requestPackageName":"` + packageName + `","requestHash":"` + requestHash + `","timestampMillis":"1730000000000"},"appIntegrity":{"appRecognitionVerdict":"PLAY_RECOGNIZED","packageName":"` + packageName + `","certificateSha256Digest":["digest-1"]},"accountDetails":{"appLicensingVerdict":"LICENSED"},"deviceIntegrity":{"deviceRecognitionVerdict":["MEETS_DEVICE_INTEGRITY"]}}}`
}

func newGoogleVerifierServer(t *testing.T, response string, status int, requestCheck func(*http.Request, []byte)) (*httptest.Server, *GooglePlayIntegrityVerifier) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		if requestCheck != nil {
			requestCheck(r, body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	verifier := &GooglePlayIntegrityVerifier{
		Client:          server.Client(),
		PackageName:     "com.duuratech.pay",
		EndpointBase:    server.URL,
		TokenSource:     staticTokenSource{},
		RequireLicensed: true,
	}
	return server, verifier
}

func TestGooglePlayIntegrityVerifierAcceptsPolicyCompliantVerdict(t *testing.T) {
	requestHash := "request-hash-1"
	server, verifier := newGoogleVerifierServer(t, googleVerdictJSON(requestHash, verifierPackageName), http.StatusOK, func(r *http.Request, body []byte) {
		if r.Header.Get("Authorization") != "Bearer test-access-token" {
			t.Errorf("missing OAuth bearer token: %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(string(body), `"integrity_token":"opaque-token"`) {
			t.Errorf("unexpected decode request: %s", body)
		}
	})
	defer server.Close()

	result, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:    GooglePlayIntegrityProvider,
		KeyID:       "android-device-key",
		Assertion:   googleAssertion(t, "opaque-token"),
		RequestHash: requestHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TrustLevel != "google-play-integrity-verified" || result.Counter == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

const verifierPackageName = "com.duuratech.pay"

func TestGooglePlayIntegrityVerifierRejectsRequestBindingMismatch(t *testing.T) {
	server, verifier := newGoogleVerifierServer(t, googleVerdictJSON("server-hash", verifierPackageName), http.StatusOK, nil)
	defer server.Close()
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:    GooglePlayIntegrityProvider,
		KeyID:       "android-device-key",
		Assertion:   googleAssertion(t, "opaque-token"),
		RequestHash: "client-hash",
	})
	if !errors.Is(err, ErrRequestBinding) {
		t.Fatalf("expected request binding error, got %v", err)
	}
}

func TestGooglePlayIntegrityVerifierRejectsUnrecognizedApp(t *testing.T) {
	response := strings.Replace(googleVerdictJSON("request-hash-1", verifierPackageName), "PLAY_RECOGNIZED", "UNRECOGNIZED_VERSION", 1)
	server, verifier := newGoogleVerifierServer(t, response, http.StatusOK, nil)
	defer server.Close()
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:    GooglePlayIntegrityProvider,
		Assertion:   googleAssertion(t, "opaque-token"),
		RequestHash: "request-hash-1",
	})
	if !errors.Is(err, ErrGooglePlayInvalidVerdict) {
		t.Fatalf("expected invalid verdict error, got %v", err)
	}
}

func TestGooglePlayIntegrityVerifierRejectsMalformedAssertion(t *testing.T) {
	server, verifier := newGoogleVerifierServer(t, `{}`, http.StatusOK, nil)
	defer server.Close()
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:  GooglePlayIntegrityProvider,
		Assertion: "not-base64",
	})
	if !errors.Is(err, ErrGooglePlayInvalidAssertion) {
		t.Fatalf("expected invalid assertion error, got %v", err)
	}
}

func TestGooglePlayIntegrityVerifierMapsDecodeEndpointFailureToUnavailable(t *testing.T) {
	server, verifier := newGoogleVerifierServer(t, `{"error":"unauthorized"}`, http.StatusUnauthorized, nil)
	defer server.Close()
	_, err := verifier.Verify(context.Background(), Challenge{}, Submission{
		Provider:    GooglePlayIntegrityProvider,
		Assertion:   googleAssertion(t, "opaque-token"),
		RequestHash: "request-hash-1",
	})
	if !errors.Is(err, ErrGooglePlayUnavailable) {
		t.Fatalf("expected provider unavailable error, got %v", err)
	}
}
