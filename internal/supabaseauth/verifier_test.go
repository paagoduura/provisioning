package supabaseauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierValidatesSupabaseUserClaims(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const issuerPath = "/auth/v1"
	var mu sync.RWMutex
	currentKey := testJWK(privateKey, "key-1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != issuerPath+"/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{currentKey}})
	}))
	defer server.Close()

	issuer := server.URL + issuerPath
	verifier, err := NewVerifier(context.Background(), issuer, "authenticated", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	valid := testToken(t, privateKey, "key-1", testClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
	}, Role: "authenticated"})
	if subject, err := verifier.Verify(context.Background(), valid); err != nil || subject != "user-123" {
		t.Fatalf("Verify() = (%q, %v), want user-123 and nil", subject, err)
	}

	tests := []struct {
		name   string
		claims testClaims
	}{
		{name: "wrong issuer", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://attacker.invalid/auth/v1", Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Role: "authenticated"}},
		{name: "wrong audience", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"other"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Role: "authenticated"}},
		{name: "wrong role", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Role: "service_role"}},
		{name: "empty subject", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}, Role: "authenticated"}},
		{name: "expired", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(now.Add(-time.Minute))}, Role: "authenticated"}},
		{name: "missing expiration", claims: testClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"}}, Role: "authenticated"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := testToken(t, privateKey, "key-1", test.claims)
			if _, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatal("Verify() accepted invalid claims")
			}
		})
	}
}

func TestVerifierRefreshesForRotatedKeyID(t *testing.T) {
	first, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.RWMutex
	keys := []any{testJWK(first, "key-1")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer server.Close()
	issuer := server.URL + "/auth/v1"
	verifier, err := NewVerifier(context.Background(), issuer, "authenticated", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	keys = []any{testJWK(first, "key-1"), testJWK(second, "key-2")}
	mu.Unlock()
	now := time.Now().UTC()
	token := testToken(t, second, "key-2", testClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: "rotated-user", Audience: jwt.ClaimStrings{"authenticated"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
	}, Role: "authenticated"})
	if subject, err := verifier.Verify(context.Background(), token); err != nil || subject != "rotated-user" {
		t.Fatalf("Verify() after key rotation = (%q, %v), want rotated-user and nil", subject, err)
	}
}

func TestVerifierRejectsSharedSecretAlgorithms(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testJWK(privateKey, "key-1")}})
	}))
	defer server.Close()
	issuer := server.URL + "/auth/v1"
	verifier, err := NewVerifier(context.Background(), issuer, "authenticated", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, testClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: "user-123", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, Role: "authenticated"})
	token.Header["kid"] = "key-1"
	serialized, err := token.SignedString([]byte("not-a-project-signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), serialized); err == nil {
		t.Fatal("Verify() accepted an HMAC-signed token")
	}
}

func TestVerifierAcceptsRS256ProjectKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testRSAJWK(&privateKey.PublicKey, "rsa-key")}})
	}))
	defer server.Close()
	issuer := server.URL + "/auth/v1"
	verifier, err := NewVerifier(context.Background(), issuer, "authenticated", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: "rsa-user", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, Role: "authenticated"})
	token.Header["kid"] = "rsa-key"
	serialized, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := verifier.Verify(context.Background(), serialized); err != nil || subject != "rsa-user" {
		t.Fatalf("Verify() with RS256 = (%q, %v), want rsa-user and nil", subject, err)
	}
}

func TestVerifierRateLimitsUnknownKIDRefreshes(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testJWK(privateKey, "known-key")}})
	}))
	defer server.Close()
	issuer := server.URL + "/auth/v1"
	verifier, err := NewVerifier(context.Background(), issuer, "authenticated", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	token := testToken(t, privateKey, "unknown-key", testClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuer, Subject: "user", Audience: jwt.ClaimStrings{"authenticated"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, Role: "authenticated"})
	for i := 0; i < 5; i++ {
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatal("Verify() accepted an unknown key ID")
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("JWKS endpoint was called %d times, want initial load plus one unknown-kid refresh", got)
	}
}

func TestVerifierRejectsNonHTTPSIssuerExceptLoopback(t *testing.T) {
	if _, err := NewVerifier(context.Background(), "http://example.com/auth/v1", "authenticated", nil); err == nil {
		t.Fatal("NewVerifier() accepted a non-HTTPS issuer")
	}
}

type testClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func testToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims testClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	serialized, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

func testJWK(key *ecdsa.PrivateKey, kid string) map[string]any {
	x := key.X.FillBytes(make([]byte, 32))
	y := key.Y.FillBytes(make([]byte, 32))
	return map[string]any{
		"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig", "key_ops": []string{"verify"},
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

func testRSAJWK(key *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "key_ops": []string{"verify"},
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}
