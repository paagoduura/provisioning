package interswitch

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type tokenRequestTransport struct{ requestKey string }

func (t *tokenRequestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := `{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`
	if req.URL.Path == "/request" {
		t.requestKey = req.Header.Get("Idempotency-Key")
		body = `{"token_reference":"provider-reference"}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func TestRequestTokenSendsStableIdempotencyHeaderOnlyWhenEnabled(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
		wantKey string
	}{
		{name: "disabled by default"},
		{name: "enabled after contract confirmation", enabled: true, wantKey: "provisioning-token-v1:session-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &tokenRequestTransport{}
			client := &Client{
				HTTP:                 &http.Client{Transport: transport},
				TokenURL:             "https://provider.example/oauth",
				RequestURL:           "https://provider.example/request",
				ClientID:             "client",
				ClientSecret:         "secret",
				IdempotencyKeyHeader: test.enabled,
			}
			if _, err := client.RequestToken(context.Background(), "session-1", "provisioning-token-v1:session-1"); err != nil {
				t.Fatal(err)
			}
			if transport.requestKey != test.wantKey {
				t.Fatalf("Idempotency-Key = %q, want %q", transport.requestKey, test.wantKey)
			}
		})
	}
}
