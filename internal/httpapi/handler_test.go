package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/auth"
	"github.com/paagoduura/provisioning/internal/service"
)

func TestRoutes(t *testing.T) {
	log := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	h := New(log, service.New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil), nil, 1<<20)
	ts := httptest.NewServer(h.Routes())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
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

type fixedAuthenticator struct{}

func (fixedAuthenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Subject: "owner-1"})))
	})
}

func TestAuthenticatedSubjectOwnsCreatedSession(t *testing.T) {
	log := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	h := New(log, service.New(memory.NewSessionRepository(), mock.CryptoService{}, mock.InterswitchAdapter{}, nil), nil, 1<<20)
	h.SetAuthenticator(fixedAuthenticator{})
	ts := httptest.NewServer(h.Routes())
	defer ts.Close()
	requestBody := `{"user_id":"different-owner","device_uid":"device-1","device_model":"model-1","transport":"ble"}`
	resp, err := http.Post(ts.URL+"/v1/provisioning-sessions", "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for mismatched owner, got %d", resp.StatusCode)
	}
}
