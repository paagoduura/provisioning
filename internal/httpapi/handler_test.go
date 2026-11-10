package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/adapters/mock"
	"github.com/paagoduura/provisioning/internal/attestation"
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

func TestDecodeRequestStrictlyAcceptsOneKnownJSONObject(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "valid object with whitespace", body: `{"user_id":"u1"}  `},
		{name: "unknown field", body: `{"user_id":"u1","admin":true}`, wantErr: true},
		{name: "second JSON value", body: `{"user_id":"u1"} {"user_id":"u2"}`, wantErr: true},
		{name: "malformed trailing data", body: `{"user_id":"u1"} unexpected`, wantErr: true},
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
