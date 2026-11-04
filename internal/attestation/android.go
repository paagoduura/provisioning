package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const AndroidPlayIntegrityProvider = "android-play-integrity"

const (
	PlayIntegrityStandard PlayIntegrityMode = "standard"
	PlayIntegrityClassic  PlayIntegrityMode = "classic"
)

type PlayIntegrityMode string

var (
	ErrAndroidUnavailable       = errors.New("android play integrity verifier is unavailable")
	ErrAndroidInvalidToken      = errors.New("invalid android play integrity token")
	ErrAndroidPackageMismatch   = errors.New("android package name mismatch")
	ErrAndroidRequestMismatch   = errors.New("android play integrity request binding mismatch")
	ErrAndroidTokenExpired      = errors.New("android play integrity token is expired or not yet valid")
	ErrAndroidAppUnrecognized   = errors.New("android app is not recognized by Google Play")
	ErrAndroidAccountUnlicensed = errors.New("android app account is not licensed")
	ErrAndroidDeviceIntegrity   = errors.New("android device integrity requirements were not met")
	ErrAndroidUnsupportedMode   = errors.New("unsupported android play integrity mode")
	ErrAndroidDecodeFailed      = errors.New("android play integrity token decode failed")
)

// PlayIntegrityTokenDecoder is deliberately separate from the verifier. Google
// decrypts and authenticates the opaque token; the verifier only evaluates the
// authenticated payload returned by that service.
type PlayIntegrityTokenDecoder interface {
	Decode(context.Context, string) (PlayIntegrityPayload, error)
}

type PlayIntegrityPayload struct {
	RequestDetails  PlayIntegrityRequestDetails  `json:"requestDetails"`
	AppIntegrity    PlayIntegrityAppIntegrity    `json:"appIntegrity"`
	DeviceIntegrity PlayIntegrityDeviceIntegrity `json:"deviceIntegrity"`
	AccountDetails  PlayIntegrityAccountDetails  `json:"accountDetails"`
}

type PlayIntegrityRequestDetails struct {
	RequestPackageName string         `json:"requestPackageName"`
	RequestHash        string         `json:"requestHash"`
	Nonce              string         `json:"nonce"`
	TimestampMillis    FlexibleUint64 `json:"timestampMillis"`
}

type PlayIntegrityAppIntegrity struct {
	AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
	PackageName             string   `json:"packageName"`
	CertificateSha256Digest []string `json:"certificateSha256Digest"`
}

type PlayIntegrityDeviceIntegrity struct {
	DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
}

type PlayIntegrityAccountDetails struct {
	AppLicensingVerdict string `json:"appLicensingVerdict"`
}

// FlexibleUint64 accepts Google's documented string representation while also
// tolerating a numeric representation from test fixtures or future gateways.
type FlexibleUint64 uint64

func (v *FlexibleUint64) UnmarshalJSON(data []byte) error {
	value := strings.TrimSpace(string(data))
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return err
	}
	*v = FlexibleUint64(parsed)
	return nil
}

// AndroidPlayIntegrityVerifier validates standard or classic Play Integrity
// verdicts. It never trusts the opaque client token directly and never stores it.
type AndroidPlayIntegrityVerifier struct {
	PackageName           string
	CloudProjectNumber    uint64
	Mode                  PlayIntegrityMode
	MaxTokenAge           time.Duration
	ClockSkew             time.Duration
	RequireLicensed       bool
	AllowedDeviceVerdicts map[string]struct{}
	Decoder               PlayIntegrityTokenDecoder
	Now                   func() time.Time
}

func (v AndroidPlayIntegrityVerifier) Verify(ctx context.Context, challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != AndroidPlayIntegrityProvider {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if strings.TrimSpace(v.PackageName) == "" || v.CloudProjectNumber == 0 || v.Decoder == nil {
		return VerifiedResult{}, ErrAndroidUnavailable
	}
	if input.KeyID == "" || input.Assertion == "" {
		return VerifiedResult{}, ErrAndroidInvalidToken
	}
	mode := v.Mode
	if mode == "" {
		mode = PlayIntegrityStandard
	}
	if mode != PlayIntegrityStandard && mode != PlayIntegrityClassic {
		return VerifiedResult{}, ErrAndroidUnsupportedMode
	}
	payload, err := v.Decoder.Decode(ctx, input.Assertion)
	if err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: %v", ErrAndroidDecodeFailed, err)
	}
	if payload.RequestDetails.RequestPackageName != v.PackageName {
		return VerifiedResult{}, ErrAndroidPackageMismatch
	}
	if err := v.validateRequest(challenge, input, payload.RequestDetails, mode); err != nil {
		return VerifiedResult{}, err
	}
	if payload.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return VerifiedResult{}, ErrAndroidAppUnrecognized
	}
	if payload.AppIntegrity.PackageName != v.PackageName {
		return VerifiedResult{}, ErrAndroidPackageMismatch
	}
	if v.RequireLicensed && payload.AccountDetails.AppLicensingVerdict != "LICENSED" {
		return VerifiedResult{}, ErrAndroidAccountUnlicensed
	}
	if !matchesDevicePolicy(payload.DeviceIntegrity.DeviceRecognitionVerdict, v.AllowedDeviceVerdicts) {
		return VerifiedResult{}, ErrAndroidDeviceIntegrity
	}
	return VerifiedResult{
		Provider:   AndroidPlayIntegrityProvider,
		KeyID:      input.KeyID,
		Counter:    uint64(payload.RequestDetails.TimestampMillis),
		TrustLevel: "android-play-integrity-verified",
	}, nil
}

func (v AndroidPlayIntegrityVerifier) validateRequest(challenge Challenge, input Submission, details PlayIntegrityRequestDetails, mode PlayIntegrityMode) error {
	if details.TimestampMillis == 0 {
		return ErrAndroidTokenExpired
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	issued := time.UnixMilli(int64(details.TimestampMillis))
	maxAge := v.MaxTokenAge
	if maxAge <= 0 {
		maxAge = 2 * time.Minute
	}
	skew := v.ClockSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	current := now()
	if issued.After(current.Add(skew)) || current.Sub(issued) > maxAge {
		return ErrAndroidTokenExpired
	}
	if mode == PlayIntegrityStandard {
		if details.RequestHash == "" || details.RequestHash != input.RequestHash {
			return ErrAndroidRequestMismatch
		}
		return nil
	}
	if details.Nonce == "" || details.Nonce != challenge.Value {
		return ErrAndroidRequestMismatch
	}
	return nil
}

func matchesDevicePolicy(verdicts []string, allowed map[string]struct{}) bool {
	if len(verdicts) == 0 || len(allowed) == 0 {
		return false
	}
	for _, verdict := range verdicts {
		if _, ok := allowed[verdict]; ok {
			return true
		}
	}
	return false
}

// GooglePlayIntegrityClient calls Google's server-side decode endpoint. The
// OAuth token source should be backed by a service account or workload identity,
// never by a credential committed to the repository.
type GooglePlayIntegrityClient struct {
	PackageName string
	HTTPClient  *http.Client
	TokenSource oauth2.TokenSource
	Endpoint    string
}

func (c GooglePlayIntegrityClient) Decode(ctx context.Context, token string) (PlayIntegrityPayload, error) {
	if strings.TrimSpace(c.PackageName) == "" || strings.TrimSpace(token) == "" || c.TokenSource == nil {
		return PlayIntegrityPayload{}, ErrAndroidUnavailable
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = "https://playintegrity.googleapis.com/v1/" + c.PackageName + ":decodeIntegrityToken"
	}
	body, err := json.Marshal(struct {
		IntegrityToken string `json:"integrity_token"`
	}{token})
	if err != nil {
		return PlayIntegrityPayload{}, err
	}
	oauthToken, err := c.TokenSource.Token()
	if err != nil {
		return PlayIntegrityPayload{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return PlayIntegrityPayload{}, err
	}
	req.Header.Set("Authorization", "Bearer "+oauthToken.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return PlayIntegrityPayload{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return PlayIntegrityPayload{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PlayIntegrityPayload{}, fmt.Errorf("google decode returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var response struct {
		TokenPayloadExternal string `json:"tokenPayloadExternal"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil || response.TokenPayloadExternal == "" {
		return PlayIntegrityPayload{}, ErrAndroidInvalidToken
	}
	var payload PlayIntegrityPayload
	if err := json.Unmarshal([]byte(response.TokenPayloadExternal), &payload); err != nil {
		return PlayIntegrityPayload{}, err
	}
	return payload, nil
}
