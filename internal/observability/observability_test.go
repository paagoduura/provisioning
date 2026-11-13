package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/paagoduura/provisioning/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
)

func TestRouteNormalizesIdentifiers(t *testing.T) {
	if got := Route("/v1/provisioning-sessions/session-123/attestation"); got != "/v1/provisioning-sessions/:id/:action" {
		t.Fatalf("route = %q", got)
	}
	if got := Route("/v1/devices/device-123/revoke"); got != "/v1/devices/:id/:action" {
		t.Fatalf("route = %q", got)
	}
}
func TestMetricsExposeApplicationSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)
	metrics.HTTPRequests.WithLabelValues("GET", "/healthz", "200").Inc()
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "provisioning_http_requests_total") {
		t.Fatalf("metrics response = %d %s", recorder.Code, recorder.Body.String())
	}
}
func TestWebhookAlertIsSignedAndRedacted(t *testing.T) {
	const secret = "test-secret"
	var receivedBody []byte
	var receivedSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedSignature = r.Header.Get("X-Alert-Signature")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	sink := NewWebhookAlertSink(server.Client(), server.URL, secret, nil)
	err := sink.Record(context.Background(), audit.Event{SessionID: "opaque-session", Type: "DEVICE_ATTESTATION_FAILED", Result: "FAILURE", Reason: "ATTESTATION_REQUEST_BINDING_MISMATCH", At: time.Unix(10, 0)})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	if receivedSignature != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("invalid signature %q", receivedSignature)
	}
	if strings.Contains(string(receivedBody), "assertion") || !strings.Contains(string(receivedBody), "ATTESTATION_REQUEST_BINDING_MISMATCH") {
		t.Fatalf("unexpected alert payload %s", receivedBody)
	}
}
