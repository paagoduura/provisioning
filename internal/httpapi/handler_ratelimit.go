package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/paagoduura/provisioning/internal/attestation"
	"github.com/paagoduura/provisioning/internal/ratelimit"
)

func (h *Handler) rateLimitIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.rateLimiter == nil {
			next.ServeHTTP(w, r)
			return
		}
		decision, err := h.rateLimiter.Allow(r.Context(), ratelimit.IPKey("api", r.RemoteAddr), ratelimit.IPPolicy)
		if err != nil {
			if h.rateRequired {
				writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if !decision.Allowed {
			writeRateLimited(w, decision)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) allow(w http.ResponseWriter, r *http.Request, key string, policy ratelimit.Policy) bool {
	if h.rateLimiter == nil {
		return true
	}
	decision, err := h.rateLimiter.Allow(r.Context(), key, policy)
	if err != nil {
		if h.rateRequired {
			writeError(w, http.StatusServiceUnavailable, "rate limiting unavailable")
			return false
		}
		return true
	}
	if !decision.Allowed {
		writeRateLimited(w, decision)
		return false
	}
	return true
}

func (h *Handler) allowSessionAction(w http.ResponseWriter, r *http.Request, action, userID, deviceID string, userPolicy, devicePolicy ratelimit.Policy) bool {
	if !h.allow(w, r, ratelimit.HashedKey("user", action, userID), userPolicy) {
		return false
	}
	if deviceID != "" && !h.allow(w, r, ratelimit.HashedKey("device", action, deviceID), devicePolicy) {
		return false
	}
	return true
}

func writeRateLimited(w http.ResponseWriter, decision ratelimit.Decision) {
	retry := decision.RetryAfter
	if retry < time.Second {
		retry = time.Second
	}
	seconds := (retry + time.Second - 1) / time.Second
	w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	writeError(w, http.StatusTooManyRequests, "too many requests")
}

func isFailedAttestation(err error) bool {
	code := attestation.FailureCode(err)
	switch code {
	case attestation.FailureChallengeNotFound, attestation.FailureChallengeExpired,
		attestation.FailureChallengeUsed, attestation.FailureDeviceNotOwned,
		attestation.FailureDeviceUnavailable, attestation.FailureProviderUnavailable,
		attestation.FailureHSMUnavailable, attestation.FailureGoogleUnavailable:
		return false
	default:
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}
}
