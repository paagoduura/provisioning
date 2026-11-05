package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const GooglePlayIntegrityProvider = "google-play-integrity"

var (
	ErrGooglePlayUnavailable      = errors.New("google play integrity provider is unavailable")
	ErrGooglePlayInvalidAssertion = errors.New("invalid google play integrity assertion")
	ErrGooglePlayInvalidVerdict   = errors.New("google play integrity verdict failed policy")
)

type GooglePlayIntegrityVerifier struct {
	Client                     *http.Client
	CredentialsJSON            []byte
	PackageName                string
	EndpointBase               string
	TokenSource                oauth2.TokenSource
	RequiredCertificateDigests map[string]struct{}
	RequireLicensed            bool
	AllowedDeviceVerdicts      map[string]struct{}
	Clock                      func() time.Time
	MaxTokenAge                time.Duration
	MaxClockSkew               time.Duration
}

type googlePlayAssertion struct {
	IntegrityToken string `json:"integrity_token"`
}

type googlePlayDecodeResponse struct {
	TokenPayloadExternal struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			RequestHash        string `json:"requestHash"`
			TimestampMillis    string `json:"timestampMillis"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
			PackageName             string   `json:"packageName"`
			CertificateSha256Digest []string `json:"certificateSha256Digest"`
		} `json:"appIntegrity"`
		AccountDetails struct {
			AppLicensingVerdict string `json:"appLicensingVerdict"`
		} `json:"accountDetails"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
	} `json:"tokenPayloadExternal"`
}

func (v GooglePlayIntegrityVerifier) Verify(ctx context.Context, _ Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != GooglePlayIntegrityProvider {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if v.Client == nil || (len(v.CredentialsJSON) == 0 && v.TokenSource == nil) || strings.TrimSpace(v.PackageName) == "" {
		return VerifiedResult{}, ErrGooglePlayUnavailable
	}
	assertion, err := decodeGooglePlayAssertion(input.Assertion)
	if err != nil {
		return VerifiedResult{}, err
	}
	client := v.Client
	if v.TokenSource != nil {
		client = oauth2.NewClient(ctx, v.TokenSource)
	} else {
		jwtConfig, err := google.JWTConfigFromJSON(v.CredentialsJSON, "https://www.googleapis.com/auth/playintegrity")
		if err != nil {
			return VerifiedResult{}, fmt.Errorf("%w: invalid credentials", ErrGooglePlayUnavailable)
		}
		client = jwtConfig.Client(ctx)
	}
	endpointBase := v.EndpointBase
	if endpointBase == "" {
		endpointBase = "https://playintegrity.googleapis.com"
	}
	endpoint := strings.TrimRight(endpointBase, "/") + "/v1/" + v.PackageName + ":decodeIntegrityToken"
	body, err := json.Marshal(map[string]string{"integrity_token": assertion.IntegrityToken})
	if err != nil {
		return VerifiedResult{}, ErrGooglePlayInvalidAssertion
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return VerifiedResult{}, ErrGooglePlayUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: decode request failed", ErrGooglePlayUnavailable)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return VerifiedResult{}, fmt.Errorf("%w: decode response failed", ErrGooglePlayUnavailable)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return VerifiedResult{}, fmt.Errorf("%w: decode endpoint returned %d", ErrGooglePlayUnavailable, resp.StatusCode)
	}
	var decoded googlePlayDecodeResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	payload := decoded.TokenPayloadExternal
	if payload.RequestDetails.RequestPackageName != v.PackageName || payload.AppIntegrity.PackageName != v.PackageName {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	if payload.RequestDetails.RequestHash != input.RequestHash {
		return VerifiedResult{}, ErrRequestBinding
	}
	if payload.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	if v.RequireLicensed && payload.AccountDetails.AppLicensingVerdict != "LICENSED" {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	if !matchesGoogleDevicePolicy(payload.DeviceIntegrity.DeviceRecognitionVerdict, v.AllowedDeviceVerdicts) {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	if len(v.RequiredCertificateDigests) > 0 && !containsConfiguredDigest(payload.AppIntegrity.CertificateSha256Digest, v.RequiredCertificateDigests) {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	counter := parseGoogleTimestamp(payload.RequestDetails.TimestampMillis)
	if counter == 0 {
		return VerifiedResult{}, ErrGooglePlayInvalidVerdict
	}
	if v.MaxTokenAge > 0 {
		now := time.Now()
		if v.Clock != nil {
			now = v.Clock()
		}
		clockSkew := v.MaxClockSkew
		if clockSkew <= 0 {
			clockSkew = 30 * time.Second
		}
		issuedAt := time.UnixMilli(int64(counter))
		if issuedAt.After(now.Add(clockSkew)) || now.Sub(issuedAt) > v.MaxTokenAge {
			return VerifiedResult{}, ErrGooglePlayInvalidVerdict
		}
	}
	return VerifiedResult{Provider: input.Provider, KeyID: input.KeyID, Counter: counter, TrustLevel: "google-play-integrity-verified"}, nil
}

func decodeGooglePlayAssertion(value string) (googlePlayAssertion, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		return googlePlayAssertion{}, ErrGooglePlayInvalidAssertion
	}
	var assertion googlePlayAssertion
	if err := json.Unmarshal(raw, &assertion); err != nil || strings.TrimSpace(assertion.IntegrityToken) == "" {
		return googlePlayAssertion{}, ErrGooglePlayInvalidAssertion
	}
	return assertion, nil
}

func matchesGoogleDevicePolicy(verdicts []string, allowed map[string]struct{}) bool {
	if len(allowed) == 0 {
		allowed = map[string]struct{}{"MEETS_DEVICE_INTEGRITY": {}}
	}
	for _, verdict := range verdicts {
		if _, ok := allowed[verdict]; ok {
			return true
		}
	}
	return false
}

func containsConfiguredDigest(actual []string, required map[string]struct{}) bool {
	for _, digest := range actual {
		if _, ok := required[digest]; ok {
			return true
		}
	}
	return false
}

func parseGoogleTimestamp(value string) uint64 {
	var timestamp uint64
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0
		}
		timestamp = timestamp*10 + uint64(char-'0')
	}
	return timestamp
}
