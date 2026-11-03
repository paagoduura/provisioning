package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const AppleAppAttestProvider = "apple-app-attest"

var (
	ErrAppleUnavailable        = errors.New("apple app attest verifier is unavailable")
	ErrAppleInvalidObject      = errors.New("invalid apple app attest object")
	ErrAppleInvalidAppID       = errors.New("apple app attest app id mismatch")
	ErrAppleInvalidKeyID       = errors.New("apple app attest key id mismatch")
	ErrAppleInvalidCertificate = errors.New("apple app attest certificate validation failed")
	ErrAppleInvalidAssertion   = errors.New("apple app attest assertion verification failed")
	ErrAppleCounterInvalid     = errors.New("apple app attest counter is invalid")
)

const (
	appleProductionAAGUID  = "appattest\x00\x00\x00\x00\x00\x00\x00"
	appleSandboxAAGUID     = "appattestsandbox"
	appleDevelopmentAAGUID = "appattestdevelop"
)

// AppleKeyStore persists the public key learned from a successful attestation.
// Implementations must be durable in staging and production; the memory store
// is intended only for tests.
type AppleKeyStore interface {
	Get(context.Context, string) (*ecdsa.PublicKey, error)
	Put(context.Context, string, *ecdsa.PublicKey) error
}

// AppleAppAttestVerifier validates Apple App Attest attestation objects and
// assertions. It never accepts an assertion until its key has been registered
// by a successful attestation validation.
type AppleAppAttestVerifier struct {
	AppID       string
	Environment string
	AppleRoot   *x509.Certificate
	Keys        AppleKeyStore
}

func (v AppleAppAttestVerifier) Verify(ctx context.Context, challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != AppleAppAttestProvider {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if strings.TrimSpace(v.AppID) == "" || v.AppleRoot == nil || v.Keys == nil {
		return VerifiedResult{}, ErrAppleUnavailable
	}
	if strings.TrimSpace(input.KeyID) == "" {
		return VerifiedResult{}, ErrAppleInvalidKeyID
	}
	envelope, err := decodeAppleAssertion(input.Assertion)
	if err != nil {
		return VerifiedResult{}, err
	}
	key, err := v.Keys.Get(ctx, input.KeyID)
	if err != nil || key == nil {
		return VerifiedResult{}, ErrAppleInvalidKeyID
	}
	counter, err := verifyAppleAssertion(v.AppID, challenge, input, envelope, key)
	if err != nil {
		return VerifiedResult{}, err
	}
	return VerifiedResult{Provider: AppleAppAttestProvider, KeyID: input.KeyID, Counter: counter, TrustLevel: "apple-app-attest-verified"}, nil
}

// RegisterAttestation validates an Apple attestation object and stores only
// the certified public key. The raw attestation object is deliberately not
// persisted because it contains receipt and certificate material unnecessary
// for subsequent assertions.
func (v AppleAppAttestVerifier) RegisterAttestation(ctx context.Context, challenge Challenge, keyID string, attestationObject string) error {
	if strings.TrimSpace(v.AppID) == "" || v.AppleRoot == nil || v.Keys == nil {
		return ErrAppleUnavailable
	}
	object, err := decodeAppleAttestation(attestationObject)
	if err != nil {
		return err
	}
	key, err := validateAppleAttestation(v.AppID, v.Environment, challenge, keyID, object, v.AppleRoot)
	if err != nil {
		return err
	}
	return v.Keys.Put(ctx, keyID, key)
}

type appleAssertion struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

type appleAttestation struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

func decodeAppleAssertion(encoded string) (appleAssertion, error) {
	raw, err := decodeAppleBase64(encoded)
	if err != nil {
		return appleAssertion{}, ErrAppleInvalidAssertion
	}
	var object appleAssertion
	if err := cbor.Unmarshal(raw, &object); err != nil || len(object.Signature) == 0 || len(object.AuthenticatorData) < 37 {
		return appleAssertion{}, ErrAppleInvalidAssertion
	}
	return object, nil
}

func decodeAppleAttestation(encoded string) (appleAttestation, error) {
	raw, err := decodeAppleBase64(encoded)
	if err != nil {
		return appleAttestation{}, ErrAppleInvalidObject
	}
	var object appleAttestation
	if err := cbor.Unmarshal(raw, &object); err != nil || object.Fmt != "apple-appattest" || len(object.AuthData) < 55 || len(object.AttStmt.X5C) < 2 {
		return appleAttestation{}, ErrAppleInvalidObject
	}
	return object, nil
}

func verifyAppleAssertion(appID string, challenge Challenge, input Submission, object appleAssertion, key *ecdsa.PublicKey) (uint64, error) {
	auth := object.AuthenticatorData
	appHash := sha256.Sum256([]byte(appID))
	if !bytes.Equal(auth[:32], appHash[:]) {
		return 0, ErrAppleInvalidAppID
	}
	clientData, err := decodeAppleClientData(input.RequestHash, challenge, input)
	if err != nil {
		return 0, err
	}
	clientHash := sha256.Sum256(clientData)
	nonceInput := append(append([]byte{}, auth...), clientHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	if !ecdsa.VerifyASN1(key, nonce[:], object.Signature) {
		return 0, ErrAppleInvalidAssertion
	}
	counter := uint64(auth[33])<<24 | uint64(auth[34])<<16 | uint64(auth[35])<<8 | uint64(auth[36])
	if counter == 0 {
		return 0, ErrAppleCounterInvalid
	}
	return counter, nil
}

// Apple client data is intentionally explicit JSON. The app must send the
// exact bytes it hashed before calling generateAssertion. This prevents the
// server from accepting a valid assertion bound to another request.
func decodeAppleClientData(requestHash string, challenge Challenge, input Submission) ([]byte, error) {
	raw, err := decodeAppleBase64(input.ClientData)
	if err != nil {
		return nil, ErrAppleInvalidAssertion
	}
	var value struct {
		Challenge   string `json:"challenge"`
		RequestHash string `json:"request_hash"`
	}
	if json.Unmarshal(raw, &value) != nil || value.Challenge != challenge.Value || value.RequestHash != requestHash {
		return nil, ErrRequestBinding
	}
	return raw, nil
}

func validateAppleAttestation(appID, environment string, challenge Challenge, keyID string, object appleAttestation, root *x509.Certificate) (*ecdsa.PublicKey, error) {
	certs := make([]*x509.Certificate, 0, len(object.AttStmt.X5C))
	for _, der := range object.AttStmt.X5C {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrAppleInvalidCertificate
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: poolFor(root), Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAppleInvalidCertificate, err)
	}
	leafKey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.Curve != elliptic.P256() {
		return nil, ErrAppleInvalidCertificate
	}
	auth := object.AuthData
	appHash := sha256.Sum256([]byte(appID))
	if !bytes.Equal(auth[:32], appHash[:]) || auth[32] != 0x41 {
		return nil, ErrAppleInvalidAppID
	}
	nonceInput := append(append([]byte{}, auth...), sha256Bytes([]byte(challenge.Value))...)
	nonce := sha256.Sum256(nonceInput)
	if !certificateNonceMatches(certs[0], nonce[:]) {
		return nil, ErrAppleInvalidCertificate
	}
	counter := auth[33:37]
	if !bytes.Equal(counter, []byte{0, 0, 0, 0}) {
		return nil, ErrAppleInvalidObject
	}
	aaguid := string(auth[37:53])
	if !validAppleAAGUID(environment, aaguid) {
		return nil, ErrAppleInvalidObject
	}
	credLen := int(auth[53])<<8 | int(auth[54])
	if len(auth) < 55+credLen {
		return nil, ErrAppleInvalidObject
	}
	credentialID := auth[55 : 55+credLen]
	keyHash := sha256.Sum256(ellipticUncompressed(leafKey))
	if !bytes.Equal(credentialID, keyHash[:]) || !equalAppleKeyID(keyID, keyHash[:]) {
		return nil, ErrAppleInvalidKeyID
	}
	return leafKey, nil
}

func certificateNonceMatches(cert *x509.Certificate, expected []byte) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.String() != "1.2.840.113635.100.8.2" {
			continue
		}
		var sequence asn1.RawValue
		if _, err := asn1.Unmarshal(extension.Value, &sequence); err != nil || sequence.Tag != asn1.TagSequence {
			return false
		}
		var value []byte
		if _, err := asn1.Unmarshal(sequence.Bytes, &value); err != nil {
			return false
		}
		return bytes.Equal(value, expected)
	}
	return false
}

func LoadAppleRootCertificatePEM(value []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, ErrAppleInvalidCertificate
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAppleInvalidCertificate, err)
	}
	return root, nil
}

func poolFor(root *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(root)
	return p
}
func sha256Bytes(value []byte) []byte { sum := sha256.Sum256(value); return sum[:] }
func ellipticUncompressed(key *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(elliptic.P256(), key.X, key.Y)
}
func equalAppleKeyID(value string, raw []byte) bool {
	decoded, err := decodeAppleBase64(value)
	return err == nil && bytes.Equal(decoded, raw)
}
func validAppleAAGUID(environment, value string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "production":
		return value == appleProductionAAGUID
	case "sandbox":
		return value == appleSandboxAAGUID
	default:
		return value == appleDevelopmentAAGUID || value == appleSandboxAAGUID
	}
}
func decodeAppleBase64(value string) ([]byte, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

// MemoryAppleKeyStore is suitable only for tests and local development.
type MemoryAppleKeyStore struct{ keys map[string]*ecdsa.PublicKey }

func NewMemoryAppleKeyStore() *MemoryAppleKeyStore {
	return &MemoryAppleKeyStore{keys: map[string]*ecdsa.PublicKey{}}
}
func (s *MemoryAppleKeyStore) Get(_ context.Context, id string) (*ecdsa.PublicKey, error) {
	key := s.keys[id]
	if key == nil {
		return nil, ErrAppleInvalidKeyID
	}
	return key, nil
}
func (s *MemoryAppleKeyStore) Put(_ context.Context, id string, key *ecdsa.PublicKey) error {
	if id == "" || key == nil {
		return ErrAppleInvalidKeyID
	}
	s.keys[id] = key
	return nil
}
