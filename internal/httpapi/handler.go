package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/domain"
	"github.com/paagoduura/provisioning/internal/registry"
	"github.com/paagoduura/provisioning/internal/service"
	"github.com/paagoduura/provisioning/internal/supabaseauth"
)

type Handler struct {
	log          *slog.Logger
	provisioning *service.Service
	attestation  *attestation.Service
	maxBodyBytes int64
	verifier     TokenVerifier
	devices      registry.Repository
}

type TokenVerifier interface {
	Verify(context.Context, string) (string, error)
}

func New(log *slog.Logger, provisioning *service.Service, attestationService *attestation.Service, maxBodyBytes int64, verifier TokenVerifier) *Handler {
	return &Handler{log: log, provisioning: provisioning, attestation: attestationService, maxBodyBytes: maxBodyBytes, verifier: verifier}
}

func (h *Handler) SetDeviceRegistry(devices registry.Repository) { h.devices = devices }

func (h *Handler) Routes() http.Handler {
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /healthz", h.health)
	publicMux.HandleFunc("GET /readyz", h.ready)
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("POST /v1/provisioning-sessions", h.createSession)
	apiMux.HandleFunc("GET /v1/devices", h.listDevices)
	apiMux.HandleFunc("POST /v1/devices", h.registerDevice)
	apiMux.HandleFunc("POST /v1/devices/", h.deviceAction)
	apiMux.HandleFunc("GET /v1/provisioning-sessions/", h.getSession)
	apiMux.HandleFunc("POST /v1/provisioning-sessions/", h.sessionAction)
	publicMux.Handle("/v1/", authenticate(h.verifier, apiMux))
	return requestID(securityHeaders(maxBody(h.maxBodyBytes, logging(h.log, publicMux))))
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
	DeviceUID   string `json:"device_uid"`
	DeviceModel string `json:"device_model"`
	Transport   string `json:"transport"`
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req createRequest
	if err := decodeRequest(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	userID := authenticatedSubject(r.Context())
	result, existing, err := h.provisioning.Create(r.Context(), service.CreateInput{UserID: userID, DeviceUID: req.DeviceUID, DeviceModel: req.DeviceModel, Transport: req.Transport}, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if result.UserID != userID {
		writeError(w, http.StatusConflict, "idempotency key already belongs to another session")
		return
	}
	status := http.StatusCreated
	if existing {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}

type deviceRequest struct {
	DeviceUID   string `json:"device_uid"`
	DeviceModel string `json:"device_model"`
	Transport   string `json:"transport"`
}

type revokeDeviceRequest struct {
	Reason string `json:"reason"`
}

func (h *Handler) registerDevice(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device registry unavailable")
		return
	}
	defer r.Body.Close()
	var req deviceRequest
	if err := decodeRequest(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.DeviceUID == "" || req.DeviceModel == "" || (req.Transport != "ble" && req.Transport != "nfc") {
		writeError(w, http.StatusBadRequest, "device_uid, device_model and transport are required")
		return
	}
	device, err := h.devices.EnsureDevice(r.Context(), authenticatedSubject(r.Context()), req.DeviceUID, req.DeviceModel, req.Transport, time.Now())
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (h *Handler) listDevices(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device registry unavailable")
		return
	}
	devices, err := h.devices.ListDevices(r.Context(), authenticatedSubject(r.Context()))
	if err != nil {
		writeRegistryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) deviceAction(w http.ResponseWriter, r *http.Request) {
	if h.devices == nil {
		writeError(w, http.StatusServiceUnavailable, "device registry unavailable")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/devices/"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "device action is required")
		return
	}
	deviceID, action := parts[0], parts[1]
	userID := authenticatedSubject(r.Context())
	switch action {
	case "revoke":
		defer r.Body.Close()
		var req revokeDeviceRequest
		if err := decodeRequest(r.Body, &req); err != nil || strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, "a revocation reason is required")
			return
		}
		if err := h.devices.RevokeDevice(r.Context(), userID, deviceID, req.Reason, time.Now()); err != nil {
			writeRegistryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "device_id": deviceID})
	case "replace":
		defer r.Body.Close()
		var req deviceRequest
		if err := decodeRequest(r.Body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if req.DeviceUID == "" || req.DeviceModel == "" || (req.Transport != "ble" && req.Transport != "nfc") {
			writeError(w, http.StatusBadRequest, "device_uid, device_model and transport are required")
			return
		}
		device, err := h.devices.ReplaceDevice(r.Context(), userID, deviceID, req.DeviceUID, req.DeviceModel, req.Transport, time.Now())
		if err != nil {
			writeRegistryError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, device)
	case "suspend", "resume", "retire":
		defer r.Body.Close()
		var req revokeDeviceRequest
		if err := decodeRequest(r.Body, &req); err != nil || strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, "a lifecycle reason is required")
			return
		}
		next := registry.StateSuspended
		if action == "resume" {
			next = registry.StateActive
		} else if action == "retire" {
			next = registry.StateRetired
		}
		if err := h.devices.SetLifecycle(r.Context(), userID, deviceID, next, req.Reason, time.Now()); err != nil {
			writeRegistryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": string(next), "device_id": deviceID})
	default:
		writeError(w, http.StatusNotFound, "unknown device action")
	}
}

func writeRegistryError(w http.ResponseWriter, err error) {
	status := http.StatusUnprocessableEntity
	code := "DEVICE_REGISTRY_ERROR"
	switch {
	case errors.Is(err, registry.ErrDeviceNotFound), errors.Is(err, registry.ErrDeviceNotOwned):
		status, code = http.StatusNotFound, "DEVICE_NOT_FOUND"
	case errors.Is(err, registry.ErrDeviceAlreadyOwned), errors.Is(err, registry.ErrKeyBoundElsewhere):
		status, code = http.StatusConflict, "DEVICE_ALREADY_BOUND"
	case errors.Is(err, registry.ErrDeviceUnavailable), errors.Is(err, registry.ErrKeyRevoked), errors.Is(err, registry.ErrKeyReplaced):
		status, code = http.StatusConflict, "DEVICE_UNAVAILABLE"
	case errors.Is(err, registry.ErrInvalidLifecycle):
		status, code = http.StatusConflict, "INVALID_DEVICE_LIFECYCLE"
	}
	writeJSON(w, status, map[string]string{"error": "device registry operation failed", "failure_code": code})
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
	if !h.requireSessionOwner(w, r, sessionID) {
		return
	}
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
		if err := decodeRequest(r.Body, &req); err != nil {
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
		if err := decodeRequest(r.Body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		result, err := h.attestation.Verify(r.Context(), sessionID, req)
		if err != nil {
			writeAttestationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	default:
		writeError(w, http.StatusNotFound, "unknown session action")
	}
}

func writeDomainError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, attestation.ErrUnsupportedProvider) {
		status = http.StatusNotImplemented
	}
	if errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, attestation.ErrChallengeNotFound) {
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
	case attestation.FailureDeviceNotOwned:
		status = http.StatusNotFound
	case attestation.FailureDeviceUnavailable, attestation.FailureKeyBoundElsewhere:
		status = http.StatusConflict
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
		if errors.Is(err, domain.ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if result.UserID != authenticatedSubject(r.Context()) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) requireSessionOwner(w http.ResponseWriter, r *http.Request, id string) bool {
	session, err := h.provisioning.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return false
	}
	if session.UserID != authenticatedSubject(r.Context()) {
		writeError(w, http.StatusNotFound, "session not found")
		return false
	}
	return true
}

type subjectContextKey struct{}

func authenticatedSubject(ctx context.Context) string {
	subject, _ := ctx.Value(subjectContextKey{}).(string)
	return subject
}

func authenticate(verifier TokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if verifier == nil {
			writeError(w, http.StatusServiceUnavailable, "authentication unavailable")
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		subject, err := verifier.Verify(r.Context(), parts[1])
		if err != nil {
			if errors.Is(err, supabaseauth.ErrVerifierUnavailable) {
				writeError(w, http.StatusServiceUnavailable, "authentication unavailable")
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid access token")
			return
		}
		if subject == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "invalid access token")
			return
		}
		ctx := context.WithValue(r.Context(), subjectContextKey{}, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeRequest(body io.Reader, destination any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
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
