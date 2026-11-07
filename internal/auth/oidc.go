package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type contextKey struct{}

var principalKey contextKey

var (
	ErrMissingBearerToken = errors.New("missing bearer token")
	ErrInvalidToken       = errors.New("invalid bearer token")
)

// Principal contains only authenticated identity claims needed by the API.
type Principal struct {
	Subject string
	Email   string
	Name    string
}

func (p Principal) Valid() bool { return strings.TrimSpace(p.Subject) != "" }

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey).(Principal)
	return principal, ok && principal.Valid()
}

// OIDCVerifier performs issuer discovery and validates JWT signatures through
// the provider JWKS. It never accepts unsigned tokens or caller-selected keys.
type OIDCVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func NewOIDCVerifier(ctx context.Context, issuerURL, audience string) (*OIDCVerifier, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	audience = strings.TrimSpace(audience)
	if issuerURL == "" || audience == "" {
		return nil, errors.New("OIDC issuer URL and audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	return &OIDCVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: audience})}, nil
}

func (v *OIDCVerifier) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		principal, err := v.verify(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="provisioning"`)
			if errors.Is(err, ErrMissingBearerToken) {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			writeAuthError(w, http.StatusUnauthorized, "invalid authentication token")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func (v *OIDCVerifier) verify(r *http.Request) (Principal, error) {
	if v == nil || v.verifier == nil {
		return Principal{}, ErrInvalidToken
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) < len("Bearer ")+1 || !strings.EqualFold(header[:len("Bearer")], "Bearer") {
		return Principal{}, ErrMissingBearerToken
	}
	token := strings.TrimSpace(header[len("Bearer"):])
	if token == "" {
		return Principal{}, ErrMissingBearerToken
	}
	idToken, err := v.verifier.Verify(r.Context(), token)
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil || strings.TrimSpace(claims.Subject) == "" {
		return Principal{}, ErrInvalidToken
	}
	return Principal{Subject: claims.Subject, Email: claims.Email, Name: claims.Name}, nil
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}` + "\n"))
}
