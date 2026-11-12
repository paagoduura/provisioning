package supabaseauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken        = errors.New("invalid Supabase access token")
	ErrVerifierUnavailable = errors.New("Supabase signing-key verifier unavailable")
)

const (
	jwksCacheTTL  = 5 * time.Minute
	maxJWKSBytes  = 1 << 20
	maxTokenBytes = 16 << 10
	maxJWKSKeys   = 100
)

type keyEntry struct {
	algorithm string
	key       any
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KeyType   string   `json:"kty"`
	Curve     string   `json:"crv"`
	KeyID     string   `json:"kid"`
	Algorithm string   `json:"alg"`
	Use       string   `json:"use"`
	KeyOps    []string `json:"key_ops"`
	X         string   `json:"x"`
	Y         string   `json:"y"`
	N         string   `json:"n"`
	E         string   `json:"e"`
}

type claims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

// Verifier validates Supabase Auth access tokens against the project's public
// JWKS keys. It supports the asymmetric ES256 and RS256 algorithms and never
// accepts shared-secret algorithms.
type Verifier struct {
	issuer   string
	audience string
	jwksURL  string
	client   *http.Client
	now      func() time.Time

	mu                   sync.Mutex
	keys                 map[string]keyEntry
	validUntil           time.Time
	retryAfter           time.Time
	unknownRefreshUntil  time.Time
	unknownRefreshFailed bool
}

func NewVerifier(ctx context.Context, issuer, audience string, client *http.Client) (*Verifier, error) {
	issuer = strings.TrimRight(issuer, "/")
	if audience == "" {
		return nil, errors.New("Supabase Auth audience must not be empty")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Supabase Auth issuer must be an absolute HTTPS URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopback(parsed.Hostname())) {
		return nil, errors.New("Supabase Auth issuer must use HTTPS")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	v := &Verifier{
		issuer:   issuer,
		audience: audience,
		jwksURL:  issuer + "/.well-known/jwks.json",
		client:   client,
		now:      time.Now,
	}
	v.mu.Lock()
	err = v.refreshLocked(ctx)
	v.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("load Supabase signing keys: %w", err)
	}
	return v, nil
}

// Verify returns the subject from a valid user access token. It rejects tokens
// that are expired, issued by another project, intended for another audience,
// or carry any role other than Supabase's authenticated user role.
func (v *Verifier) Verify(ctx context.Context, raw string) (string, error) {
	if len(raw) == 0 || len(raw) > maxTokenBytes {
		return "", ErrInvalidToken
	}
	parsedClaims := &claims{}
	token, err := jwt.ParseWithClaims(raw, parsedClaims, func(token *jwt.Token) (any, error) {
		algorithm := token.Method.Alg()
		if algorithm != "ES256" && algorithm != "RS256" {
			return nil, ErrInvalidToken
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 256 {
			return nil, ErrInvalidToken
		}
		entry, err := v.key(ctx, kid)
		if err != nil {
			return nil, err
		}
		if entry.algorithm != algorithm {
			return nil, ErrInvalidToken
		}
		return entry.key, nil
	},
		jwt.WithValidMethods([]string{"ES256", "RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(v.now),
	)
	if err != nil {
		if errors.Is(err, ErrVerifierUnavailable) {
			return "", ErrVerifierUnavailable
		}
		return "", fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if token == nil || !token.Valid || parsedClaims.Subject == "" || parsedClaims.Role != "authenticated" {
		return "", ErrInvalidToken
	}
	return parsedClaims.Subject, nil
}

// Ready confirms that the verifier has a usable, non-expired asymmetric JWKS
// cache. When the cache has expired it refreshes from the configured issuer;
// the caller supplies the bounded readiness timeout.
func (v *Verifier) Ready(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) > 0 && v.now().Before(v.validUntil) {
		return nil
	}
	return v.refreshLocked(ctx)
}

func (v *Verifier) key(ctx context.Context, kid string) (keyEntry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now()
	if now.Before(v.validUntil) {
		if entry, ok := v.keys[kid]; ok {
			return entry, nil
		}
		if now.Before(v.unknownRefreshUntil) {
			if v.unknownRefreshFailed {
				return keyEntry{}, ErrVerifierUnavailable
			}
			return keyEntry{}, ErrInvalidToken
		}
		v.unknownRefreshUntil = now.Add(15 * time.Second)
	} else if now.Before(v.retryAfter) {
		return keyEntry{}, ErrVerifierUnavailable
	}
	// Refresh on expiry and immediately for an unknown kid so signing-key
	// rotation is picked up without waiting for the normal cache interval.
	if err := v.refreshLocked(ctx); err != nil {
		if now.Before(v.validUntil) {
			v.unknownRefreshFailed = true
		}
		return keyEntry{}, err
	}
	v.unknownRefreshFailed = false
	entry, ok := v.keys[kid]
	if !ok {
		return keyEntry{}, ErrInvalidToken
	}
	return entry, nil
}

func (v *Verifier) refreshLocked(ctx context.Context) error {
	if v.now().Before(v.retryAfter) {
		return ErrVerifierUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return v.failedRefresh("create signing-key request")
	}
	response, err := v.client.Do(request)
	if err != nil {
		return v.failedRefresh("fetch signing keys")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return v.failedRefresh(fmt.Sprintf("signing-key endpoint returned HTTP %d", response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return v.failedRefresh("read signing-key document")
	}
	var document jwksDocument
	if err := json.Unmarshal(body, &document); err != nil || len(document.Keys) == 0 || len(document.Keys) > maxJWKSKeys {
		return v.failedRefresh("invalid signing-key document")
	}
	keys := make(map[string]keyEntry, len(document.Keys))
	for _, candidate := range document.Keys {
		entry, supported, err := candidate.publicKey()
		if err != nil {
			return v.failedRefresh("invalid public signing key")
		}
		if !supported {
			continue
		}
		if _, duplicate := keys[candidate.KeyID]; duplicate {
			return v.failedRefresh("duplicate signing-key ID")
		}
		keys[candidate.KeyID] = entry
	}
	if len(keys) == 0 {
		return v.failedRefresh("no supported asymmetric signing keys")
	}
	v.keys = keys
	v.validUntil = v.now().Add(jwksCacheTTL)
	v.retryAfter = time.Time{}
	return nil
}

func (v *Verifier) failedRefresh(reason string) error {
	v.retryAfter = v.now().Add(15 * time.Second)
	return fmt.Errorf("%w: %s", ErrVerifierUnavailable, reason)
}

func (k jwk) publicKey() (keyEntry, bool, error) {
	if k.KeyID == "" {
		return keyEntry{}, false, nil
	}
	if k.Use != "" && k.Use != "sig" {
		return keyEntry{}, false, nil
	}
	if len(k.KeyOps) != 0 && !contains(k.KeyOps, "verify") {
		return keyEntry{}, false, nil
	}
	switch k.Algorithm {
	case "ES256":
		if k.KeyType != "EC" || k.Curve != "P-256" {
			return keyEntry{}, false, errors.New("ES256 key must be an EC P-256 key")
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return keyEntry{}, false, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return keyEntry{}, false, err
		}
		curve := elliptic.P256()
		if len(x) != 32 || len(y) != 32 || !curve.IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
			return keyEntry{}, false, errors.New("invalid P-256 public point")
		}
		return keyEntry{algorithm: k.Algorithm, key: &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}, true, nil
	case "RS256":
		if k.KeyType != "RSA" {
			return keyEntry{}, false, errors.New("RS256 key must be RSA")
		}
		modulus, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return keyEntry{}, false, err
		}
		exponent, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return keyEntry{}, false, err
		}
		n := new(big.Int).SetBytes(modulus)
		eBig := new(big.Int).SetBytes(exponent)
		if n.BitLen() < 2048 || !eBig.IsInt64() {
			return keyEntry{}, false, errors.New("invalid RSA public key size")
		}
		e := eBig.Int64()
		if e < 3 || e > int64(^uint(0)>>1) || e%2 == 0 {
			return keyEntry{}, false, errors.New("invalid RSA public exponent")
		}
		return keyEntry{algorithm: k.Algorithm, key: &rsa.PublicKey{N: n, E: int(e)}}, true, nil
	default:
		return keyEntry{}, false, nil
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
