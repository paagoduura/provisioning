package observability

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/paagoduura/provisioning/internal/audit"
)

type Metrics struct {
	HTTPRequests, DependencyRequests, AttestationFailures, SecurityEvents, RateLimitDenied *prometheus.CounterVec
	HTTPDuration, DependencyDuration                                                       *prometheus.HistogramVec
	Registry                                                                               prometheus.Registerer
	Gatherer                                                                               prometheus.Gatherer
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	gatherer, ok := reg.(prometheus.Gatherer)
	if !ok {
		panic("observability registerer must also implement prometheus.Gatherer")
	}
	m := &Metrics{Registry: reg, Gatherer: gatherer,
		HTTPRequests:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "provisioning_http_requests_total", Help: "Total HTTP requests handled."}, []string{"method", "route", "status"}),
		HTTPDuration:        prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "provisioning_http_request_duration_seconds", Help: "HTTP request duration in seconds."}, []string{"method", "route"}),
		DependencyRequests:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "provisioning_dependency_requests_total", Help: "Total dependency operations by outcome."}, []string{"dependency", "operation", "outcome"}),
		DependencyDuration:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "provisioning_dependency_duration_seconds", Help: "Dependency operation duration in seconds."}, []string{"dependency", "operation"}),
		AttestationFailures: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "provisioning_attestation_failures_total", Help: "Attestation failures by provider and stable failure code."}, []string{"provider", "failure_code"}),
		SecurityEvents:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "provisioning_security_events_total", Help: "Security-relevant audit events."}, []string{"event_type", "result", "reason"}),
		RateLimitDenied:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "provisioning_rate_limit_denied_total", Help: "Requests rejected by abuse controls."}, []string{"scope", "route"}),
	}
	for _, c := range []prometheus.Collector{m.HTTPRequests, m.HTTPDuration, m.DependencyRequests, m.DependencyDuration, m.AttestationFailures, m.SecurityEvents, m.RateLimitDenied} {
		reg.MustRegister(c)
	}
	return m
}
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Gatherer, promhttp.HandlerOpts{EnableOpenMetrics: true})
}
func (m *Metrics) RecordDependency(dep, op string, started time.Time, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	m.DependencyRequests.WithLabelValues(safeLabel(dep, "unknown"), safeLabel(op, "unknown"), outcome).Inc()
	m.DependencyDuration.WithLabelValues(safeLabel(dep, "unknown"), safeLabel(op, "unknown")).Observe(time.Since(started).Seconds())
}
func (m *Metrics) RecordAttestationFailure(provider, code string) {
	m.AttestationFailures.WithLabelValues(safeLabel(provider, "unknown"), safeLabel(code, "unknown")).Inc()
}
func (m *Metrics) RecordSecurityEvent(event audit.Event) {
	m.SecurityEvents.WithLabelValues(safeLabel(event.Type, "unknown"), safeLabel(event.Result, "unknown"), safeLabel(event.Reason, "none")).Inc()
}
func (m *Metrics) RecordRateLimitDenied(scope, route string) {
	m.RateLimitDenied.WithLabelValues(safeLabel(scope, "unknown"), safeLabel(route, "unknown")).Inc()
}
func safeLabel(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if len(v) > 96 {
		return v[:96]
	}
	return v
}

func MiddlewareWithTracer(m *Metrics, tracer trace.Tracer, next http.Handler) http.Handler {
	if tracer == nil {
		tracer = otel.Tracer("provisioning/http")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := Route(r.URL.Path)
		ctx, span := tracer.Start(r.Context(), r.Method+" "+route, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		sw := &statusWriter{ResponseWriter: w}
		started := time.Now()
		next.ServeHTTP(sw, r.WithContext(ctx))
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		span.SetAttributes(attribute.String("http.request.method", r.Method), attribute.String("http.route", route), attribute.Int("http.response.status_code", status))
		if status >= 500 {
			span.RecordError(errors.New(http.StatusText(status)))
		}
		if m != nil {
			m.HTTPRequests.WithLabelValues(r.Method, route, fmt.Sprint(status)).Inc()
			m.HTTPDuration.WithLabelValues(r.Method, route).Observe(time.Since(started).Seconds())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}
func Route(path string) string {
	if strings.HasPrefix(path, "/v1/provisioning-sessions/") {
		return "/v1/provisioning-sessions/:id/:action"
	}
	if strings.HasPrefix(path, "/v1/devices/") {
		return "/v1/devices/:id/:action"
	}
	switch path {
	case "/v1/provisioning-sessions", "/v1/devices", "/healthz", "/readyz", "/metrics":
		return path
	default:
		return "/other"
	}
}

type JSONSink struct{ log *slog.Logger }

func NewJSONSink(log *slog.Logger) *JSONSink { return &JSONSink{log: log} }
func (s *JSONSink) Record(_ context.Context, event audit.Event) error {
	if s == nil || s.log == nil {
		return nil
	}
	s.log.Info("audit_event", "session_id", event.SessionID, "event_type", event.Type, "result", event.Result, "reason_code", event.Reason, "actor_id", event.ActorID, "device_id", event.DeviceID, "provider", event.Provider, "request_id", event.RequestID, "event_at", event.At)
	return nil
}

type MultiSink struct{ sinks []audit.Sink }

func NewMultiSink(sinks ...audit.Sink) *MultiSink { return &MultiSink{sinks: sinks} }
func (s *MultiSink) Record(ctx context.Context, event audit.Event) error {
	var first error
	for _, sink := range s.sinks {
		if sink == nil {
			continue
		}
		if err := sink.Record(ctx, event); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type AuditMetricsSink struct {
	Next    audit.Sink
	Metrics *Metrics
}

func (s *AuditMetricsSink) Record(ctx context.Context, event audit.Event) error {
	if s.Metrics != nil {
		s.Metrics.RecordSecurityEvent(event)
		if strings.HasPrefix(event.Type, "DEVICE_ATTESTATION") && event.Result == "FAILURE" {
			s.Metrics.RecordAttestationFailure(event.Provider, event.Reason)
		}
	}
	if s.Next == nil {
		return nil
	}
	return s.Next.Record(ctx, event)
}

type WebhookAlertSink struct {
	client      *http.Client
	url, secret string
}

func NewWebhookAlertSink(client *http.Client, url, secret string, _ *slog.Logger) *WebhookAlertSink {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &WebhookAlertSink{client: client, url: strings.TrimSpace(url), secret: secret}
}
func (s *WebhookAlertSink) Record(ctx context.Context, event audit.Event) error {
	if s == nil || s.url == "" || event.Result != "FAILURE" {
		return nil
	}
	body, err := json.Marshal(map[string]any{"event_type": event.Type, "result": event.Result, "reason_code": event.Reason, "session_id": event.SessionID, "device_id": event.DeviceID, "provider": event.Provider, "request_id": event.RequestID, "event_at": event.At.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Alert-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("alert webhook returned HTTP %d", response.StatusCode)
	}
	return nil
}
