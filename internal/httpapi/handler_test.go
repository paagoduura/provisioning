package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/internal/service"
	"github.com/paagoduura/provisioning/internal/supabaseauth"
)

func TestHealthRoutesRemainPublicAndAPIRoutesRequireAuthentication(t *testing.T) {
	h := newTestHandler(testVerifier{})
	for _, test := range []struct {
		path string
		want int
	}{
		{path: "/healthz", want: http.StatusOK},
		{path: "/readyz", want: http.StatusOK},
		{path: "/v1/provisioning-sessions/example", want: http.StatusUnauthorized},
	} {
		recorder := httptest.NewRecorder()
		h.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.want {
			t.Errorf("GET %s returned %d, want %d", test.path, recorder.Code, test.want)
		}
	}
}

func TestAPIIsUnavailableWithoutConfiguredVerifier(t *testing.T) {
	h := newTestHandler(nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("API without verifier returned %d, want 503", recorder.Code)
	}
}

func TestCreateSessionUsesVerifiedSubjectAndRejectsClientIdentity(t *testing.T) {
	h := newTestHandler(testVerifier{"valid-user-token": "user-123"})
	body := `{"device_uid":"device-1","device_model":"wearable-v1","transport":"ble"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer valid-user-token")
	request.Header.Set("Idempotency-Key", "create-user-123")
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var created domain.ProvisioningSession
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.UserID != "user-123" {
		t.Fatalf("session owner = %q, want verified subject user-123", created.UserID)
	}

	spoofed := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(`{"user_id":"victim","device_uid":"device-2","device_model":"wearable-v1","transport":"ble"}`))
	spoofed.Header.Set("Authorization", "Bearer valid-user-token")
	spoofed.Header.Set("Idempotency-Key", "create-spoofed-user")
	spoofedRecorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(spoofedRecorder, spoofed)
	if spoofedRecorder.Code != http.StatusBadRequest {
		t.Fatalf("client-supplied user_id returned %d, want 400", spoofedRecorder.Code)
	}
}

func TestSessionReadAndActionsAreOwnerScoped(t *testing.T) {
	h := newTestHandler(testVerifier{"owner-token": "owner-1", "other-token": "owner-2"})
	created := createSessionForTest(t, h, "owner-token", "shared-idempotency")

	for _, test := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "read", method: http.MethodGet, path: "/v1/provisioning-sessions/" + created.ID},
		{name: "transition", method: http.MethodPost, path: "/v1/provisioning-sessions/" + created.ID + "/device-discovery"},
		{name: "attestation challenge", method: http.MethodPost, path: "/v1/provisioning-sessions/" + created.ID + "/attestation-challenges"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
			request.Header.Set("Authorization", "Bearer other-token")
			recorder := httptest.NewRecorder()
			h.Routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("unauthorized owner request returned %d, want 404", recorder.Code)
			}
			if strings.Contains(recorder.Body.String(), created.ID) {
				t.Fatal("unauthorized response disclosed the session ID")
			}
		})
	}

	ownerRequest := httptest.NewRequest(http.MethodGet, "/v1/provisioning-sessions/"+created.ID, nil)
	ownerRequest.Header.Set("Authorization", "Bearer owner-token")
	ownerRecorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(ownerRecorder, ownerRequest)
	if ownerRecorder.Code != http.StatusOK {
		t.Fatalf("owner read returned %d, want 200", ownerRecorder.Code)
	}
	var current domain.ProvisioningSession
	if err := json.Unmarshal(ownerRecorder.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if current.State != domain.StateCreated {
		t.Fatalf("unauthorized action changed session state to %q", current.State)
	}
}

func TestIdempotencyKeyCannotExposeAnotherOwnersSession(t *testing.T) {
	h := newTestHandler(testVerifier{"owner-token": "owner-1", "other-token": "owner-2"})
	createSessionForTest(t, h, "owner-token", "cross-owner-key")
	request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(`{"device_uid":"other-device","device_model":"wearable-v1","transport":"ble"}`))
	request.Header.Set("Authorization", "Bearer other-token")
	request.Header.Set("Idempotency-Key", "cross-owner-key")
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("cross-owner idempotency reuse returned %d, want 409", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "owner-1") {
		t.Fatal("idempotency conflict disclosed the other user's identity")
	}
}

func TestAuthenticationFailuresDoNotReachAPI(t *testing.T) {
	for _, test := range []struct {
		name     string
		token    string
		verifier TokenVerifier
		want     int
	}{
		{name: "invalid token", token: "bad-token", verifier: testVerifier{}, want: http.StatusUnauthorized},
		{name: "JWKS unavailable", token: "unavailable-token", verifier: unavailableVerifier{}, want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newTestHandler(test.verifier)
			request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(`{}`))
			request.Header.Set("Authorization", "Bearer "+test.token)
			recorder := httptest.NewRecorder()
			h.Routes().ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("request returned %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

func TestGooglePlayFailureHTTPMapping(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "unavailable", err: attestation.ErrGooglePlayUnavailable, want: http.StatusServiceUnavailable},
		{name: "invalid verdict", err: attestation.ErrGooglePlayInvalidVerdict, want: http.StatusUnprocessableEntity},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeAttestationError(recorder, test.err)
			if recorder.Code != test.want {
				t.Fatalf("got status %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

func TestDecodeRequestStrictlyAcceptsOneKnownJSONObject(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "valid object with whitespace", body: `{"device_uid":"d1","device_model":"model","transport":"ble"}  `},
		{name: "client-supplied identity is unknown", body: `{"user_id":"u1","device_uid":"d1","device_model":"model","transport":"ble"}`, wantErr: true},
		{name: "unknown field", body: `{"device_uid":"d1","admin":true}`, wantErr: true},
		{name: "second JSON value", body: `{"device_uid":"d1"} {"device_uid":"d2"}`, wantErr: true},
		{name: "malformed trailing data", body: `{"device_uid":"d1"} unexpected`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var request createRequest
			err := decodeRequest(bytes.NewBufferString(test.body), &request)
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeRequest error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestAttestationSubmissionRejectsClientRequestHash(t *testing.T) {
	var submission attestation.Submission
	if err := decodeRequest(bytes.NewBufferString(`{"challenge_id":"c","provider":"aws-kms","key_id":"k","assertion":"a","request_hash":"client-controlled"}`), &submission); err == nil {
		t.Fatal("client-supplied request_hash was accepted")
	}
}

type testVerifier map[string]string

func (v testVerifier) Verify(_ context.Context, token string) (string, error) {
	if subject, ok := v[token]; ok {
		return subject, nil
	}
	return "", supabaseauth.ErrInvalidToken
}

type unavailableVerifier struct{}

func (unavailableVerifier) Verify(context.Context, string) (string, error) {
	return "", supabaseauth.ErrVerifierUnavailable
}

func newTestHandler(verifier TokenVerifier) *Handler {
	log := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	provisioning := service.New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil)
	return New(log, provisioning, nil, 1<<20, verifier)
}

func createSessionForTest(t *testing.T, h *Handler, token, idempotencyKey string) domain.ProvisioningSession {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/provisioning-sessions", strings.NewReader(`{"device_uid":"device-1","device_model":"wearable-v1","transport":"ble"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	recorder := httptest.NewRecorder()
	h.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var session domain.ProvisioningSession
	if err := json.Unmarshal(recorder.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	return session
}
