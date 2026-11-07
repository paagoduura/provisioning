package httpapi

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/adapters/memory"
	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/internal/service"
)

type Handler struct {
	log          *slog.Logger
	provisioning *service.Service
	attestation  *attestation.Service
	devices      *service.DeviceService
	maxBodyBytes int64
}

func New(log *slog.Logger, provisioning *service.Service, attestationService *attestation.Service, maxBodyBytes int64) *Handler {
	return &Handler{log: log, provisioning: provisioning, attestation: attestationService, maxBodyBytes: maxBodyBytes}
}

func (h *Handler) SetDeviceRegistry(registry *service.DeviceService) { h.devices = registry }

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.health)
	mux.HandleFunc("GET /readyz", h.ready)
	mux.HandleFunc("POST /v1/provisioning-sessions", h.createSession)
	mux.HandleFunc("GET /v1/provisioning-sessions/", h.getSession)
	mux.HandleFunc("POST /v1/provisioning-sessions/", h.sessionAction)
	mux.HandleFunc("GET /v1/devices/", h.getDevice)
	return requestID(securityHeaders(maxBody(h.maxBodyBytes, logging(h.log, mux))))
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if h.provisioning == nil {
		writeError(w, http.StatusServiceUnavailable, "provisioning service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

type createRequest struct {
	UserID      string `json:"user_id"`
	DeviceUID   string `json:"device_uid"`
	DeviceModel string `json:"device_model"`
	Transport   string `json:"transport"`
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	result, existing, err := h.provisioning.Create(r.Context(), service.CreateInput{UserID: req.UserID, DeviceUID: req.DeviceUID, DeviceModel: req.DeviceModel, Transport: req.Transport}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusCreated
	if existing {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

type challengeRequest struct {
	RequestHash string `json:"request_hash"`
}
type challengeResponse struct {
	ID        string    `json:"id"`
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) sessionAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/provisioning-sessions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "session action is required")
		return
	}
	sessionID, action := parts[0], parts[1]
	switch action {
	case "device-discovery":
		result, err := h.provisioning.Discover(r.Context(), sessionID)
		if err != nil {
			writeDomainError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "attestation-challenges":
		if h.attestation == nil {
			writeError(w, http.StatusServiceUnavailable, "attestation service unavailable")
			return
		}
		var req challengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		result, err := h.attestation.IssueChallenge(r.Context(), sessionID, req.RequestHash)
		if err != nil {
			writeAttestationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, challengeResponse{ID: result.ID, Challenge: result.Value, ExpiresAt: result.ExpiresAt})
	case "attestation":
		if h.attestation == nil {
			writeError(w, http.StatusServiceUnavailable, "attestation service unavailable")
			return
		}
		var req attestation.Submission
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		result, err := h.attestation.Verify(r.Context(), sessionID, req)
		if err != nil {
			h.log.Error("attestation_verification_failed", "failure_code", attestation.FailureCode(err), "error", err, "request_id", r.Header.Get("X-Request-ID"))
			writeAttestationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "attestation-registration":
		if h.attestation == nil {
			writeError(w, http.StatusServiceUnavailable, "attestation service unavailable")
			return
		}
		var req attestation.Submission
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if err := h.attestation.Register(r.Context(), sessionID, req); err != nil {
			h.log.Error("attestation_registration_failed", "failure_code", attestation.FailureCode(err), "error", err, "request_id", r.Header.Get("X-Request-ID"))
			writeAttestationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"status": "registered"})
	default:
		writeError(w, http.StatusNotFound, "unknown session action")
	}
}

func writeDomainError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, attestation.ErrUnsupportedProvider) {
		status = http.StatusNotImplemented
	}
	if errors.Is(err, memory.ErrNotFound) || errors.Is(err, attestation.ErrChallengeNotFound) {
		status = http.StatusNotFound
	}
	writeError(w, status, err.Error())
}

func writeAttestationError(w http.ResponseWriter, err error) {
	code := attestation.FailureCode(err)
	status := http.StatusUnprocessableEntity
	switch code {
	case attestation.FailureChallengeNotFound:
		status = http.StatusNotFound
	case attestation.FailureChallengeExpired:
		status = http.StatusGone
	case attestation.FailureChallengeUsed:
		status = http.StatusConflict
	case attestation.FailureCounterRollback:
		status = http.StatusConflict
	case attestation.FailureDeviceRevoked:
		status = http.StatusForbidden
	case attestation.FailureProviderUnavailable:
		status = http.StatusNotImplemented
	case attestation.FailureHSMUnavailable:
		status = http.StatusServiceUnavailable
	case attestation.FailureGoogleUnavailable:
		status = http.StatusServiceUnavailable
	case attestation.FailureRequestBinding:
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": "attestation verification failed", "failure_code": code})
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/provisioning-sessions/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}
	result, err := h.provisioning.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, memory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) getDevice(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device registry unavailable")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/devices/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "device id is required")
		return
	}
	device, err := h.devices.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
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

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if len(id) == 0 || len(id) > 128 {
			id = newRequestID()
		}
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "request-id-unavailable"
	}
	return fmt.Sprintf("req_%x", b)
}

func maxBody(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		log.Info("http_request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration_ms", time.Since(started).Milliseconds(), "request_id", r.Header.Get("X-Request-ID"))
	})
}
