package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/paagoduura/provisioning/internal/domain"
)

const canonicalRequestVersion = 1

// CanonicalProvisioningRequest is deliberately a closed, server-built schema.
// Its JSON field order is lexicographic, its values are I-JSON strings or an
// integer, and encoding/json emits no whitespace, making this representation
// RFC 8785-compatible without accepting arbitrary client JSON.
type CanonicalProvisioningRequest struct {
	DeviceID    string `json:"device_id"`
	DeviceModel string `json:"device_model"`
	Operation   string `json:"operation"`
	SessionID   string `json:"session_id"`
	Transport   string `json:"transport"`
	Version     int    `json:"version"`
}

func buildCanonicalProvisioningRequest(session domain.ProvisioningSession, challenge string) (CanonicalProvisioningRequest, []byte, string, error) {
	if session.ID == "" || session.DeviceID == "" || session.DeviceModel == "" || session.Transport == "" || challenge == "" {
		return CanonicalProvisioningRequest{}, nil, "", errors.New("canonical provisioning request requires an identified session and challenge")
	}
	request := CanonicalProvisioningRequest{
		DeviceID:    session.DeviceID,
		DeviceModel: session.DeviceModel,
		Operation:   "provision",
		SessionID:   session.ID,
		Transport:   session.Transport,
		Version:     canonicalRequestVersion,
	}
	// The challenge is part of the signed client-data envelope. It is not
	// duplicated in this request object, avoiding a circular digest definition.
	var canonicalBuffer bytes.Buffer
	encoder := json.NewEncoder(&canonicalBuffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(request); err != nil {
		return CanonicalProvisioningRequest{}, nil, "", err
	}
	canonical := bytes.TrimSuffix(canonicalBuffer.Bytes(), []byte{'\n'})
	digestInput := append(append([]byte("provisioning-request-v1\n"), canonical...), append([]byte("\nchallenge="), challenge...)...)
	digest := sha256.Sum256(digestInput)
	return request, canonical, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
