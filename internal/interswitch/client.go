package interswitch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paagoduura/provisioning/internal/service"
)

type Client struct {
	HTTP          *http.Client
	TokenURL      string
	RequestURL    string
	ClientID      string
	ClientSecret  string
	WebhookSecret []byte
	MaxClockSkew  time.Duration
	mu            sync.Mutex
	accessToken   string
	expiresAt     time.Time
}
type oauthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}
type requestResponse struct {
	Reference string `json:"token_reference"`
}

func (c *Client) RequestToken(ctx context.Context, sessionID string) (string, error) {
	if strings.TrimSpace(sessionID) == "" || c == nil || c.HTTP == nil || c.RequestURL == "" {
		return "", errors.New("interswitch token request is not configured")
	}
	if err := requireHTTPS(c.RequestURL); err != nil {
		return "", err
	}
	token, err := c.oauthToken(ctx)
	if err != nil {
		return "", err
	}
	body := strings.NewReader(`{"session_id":` + strconv.Quote(sessionID) + `}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RequestURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("interswitch token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("interswitch token request returned HTTP %d", resp.StatusCode)
	}
	var decoded requestResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode interswitch token response: %w", err)
	}
	if decoded.Reference == "" {
		return "", errors.New("interswitch response did not contain token_reference")
	}
	return decoded.Reference, nil
}
func (c *Client) oauthToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.accessToken != "" && time.Now().Before(c.expiresAt.Add(-30*time.Second)) {
		token := c.accessToken
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()
	if c.TokenURL == "" || c.ClientID == "" || c.ClientSecret == "" {
		return "", errors.New("interswitch OAuth client credentials are not configured")
	}
	if err := requireHTTPS(c.TokenURL); err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("interswitch OAuth token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("interswitch OAuth token endpoint returned HTTP %d", resp.StatusCode)
	}
	var decoded oauthResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&decoded); err != nil || decoded.AccessToken == "" || decoded.TokenType == "" {
		return "", errors.New("invalid interswitch OAuth token response")
	}
	c.mu.Lock()
	c.accessToken = decoded.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(decoded.ExpiresIn) * time.Second)
	c.mu.Unlock()
	return decoded.AccessToken, nil
}
func (c *Client) VerifyTokenWebhook(ctx context.Context, body []byte, headers map[string]string) (service.TokenWebhook, error) {
	if c == nil || len(c.WebhookSecret) == 0 {
		return service.TokenWebhook{}, errors.New("interswitch webhook secret is not configured")
	}
	timestamp := headers["X-Interswitch-Timestamp"]
	signature := headers["X-Interswitch-Signature"]
	eventID := headers["X-Interswitch-Event-Id"]
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || eventID == "" || signature == "" {
		return service.TokenWebhook{}, errors.New("interswitch webhook signature headers are incomplete")
	}
	maxSkew := c.MaxClockSkew
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	if delta := time.Since(time.Unix(seconds, 0)); delta > maxSkew || delta < -maxSkew {
		return service.TokenWebhook{}, errors.New("interswitch webhook timestamp outside replay window")
	}
	mac := hmac.New(sha256.New, c.WebhookSecret)
	_, _ = mac.Write([]byte(timestamp + "\n"))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	supplied := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(signature)), "sha256=")
	decoded, err := hex.DecodeString(supplied)
	if err != nil || len(decoded) != sha256.Size || subtle.ConstantTimeCompare(decoded, []byte(expected)) != 1 {
		return service.TokenWebhook{}, errors.New("invalid interswitch webhook signature")
	}
	var payload struct {
		SessionID      string `json:"session_id"`
		TokenReference string `json:"token_reference"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.SessionID == "" || payload.TokenReference == "" {
		return service.TokenWebhook{}, errors.New("invalid interswitch webhook payload")
	}
	select {
	case <-ctx.Done():
		return service.TokenWebhook{}, ctx.Err()
	default:
	}
	return service.TokenWebhook{SessionID: payload.SessionID, TokenReference: payload.TokenReference, EventID: eventID}, nil
}

var _ service.TokenPort = (*Client)(nil)
var _ service.TokenWebhookVerifier = (*Client)(nil)

func requireHTTPS(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("interswitch endpoints must use HTTPS")
	}
	return nil
}
