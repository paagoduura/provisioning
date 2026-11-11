package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const AppleAppAttestProvider = "apple-app-attest"

var (
	ErrAppleUnavailable        = errors.New("apple app attest verifier is unavailable")
	ErrAppleInvalidObject      = errors.New("invalid apple app attest object")
	ErrAppleInvalidCertificate = errors.New("invalid apple app attest certificate chain")
	ErrAppleInvalidNonce       = errors.New("invalid apple app attest nonce")
	ErrAppleInvalidAppID       = errors.New("apple app attest app id mismatch")
	ErrAppleInvalidEnvironment = errors.New("apple app attest environment mismatch")
	ErrAppleInvalidCredential  = errors.New("apple app attest credential mismatch")
	ErrAppleInvalidAssertion   = errors.New("invalid apple app attest assertion")
	ErrAppleCounterRollback    = errors.New("apple app attest counter did not increase")
	ErrAppleClientData         = errors.New("invalid apple app attest client data")
)

var appleCredentialExtensionOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// AppleAppAttestKey is the minimum persisted state required to validate a
// subsequent App Attest assertion. PublicKeyDER must contain a PKIX-encoded
// P-256 public key extracted from a previously validated attestation object.
type AppleAppAttestKey struct {
	PublicKeyDER  []byte
	Counter       uint32
	BundleVersion string
	Environment   string
}

// AppleAppAttestKeyLookup supplies a previously registered App Attest key.
// Implementations must read from durable storage and must not accept a key
// supplied by the caller.
type AppleAppAttestKeyLookup interface {
	LookupAppleAppAttestKey(context.Context, string) (AppleAppAttestKey, error)
}

// AppleAppAttestVerifier validates Apple's attestation and assertion formats.
// Root must contain Apple's current App Attest root certificate. The verifier
// intentionally has no software or development fallback.
type AppleAppAttestVerifier struct {
	Root        *x509.CertPool
	TeamID      string
	BundleID    string
	Environment string // "development" or "production"
	Keys        AppleAppAttestKeyLookup
	Clock       func() time.Time
}

type appleAttestationObject struct {
	Format        string
	AuthData      []byte
	LeafCert      *x509.Certificate
	Chain         []*x509.Certificate
	Credential    []byte
	PublicKey     *ecdsa.PublicKey
	BundleVersion string
}

type appleAssertionObject struct {
	Signature []byte
	AuthData  []byte
}

type appleClientData struct {
	Challenge   string `json:"challenge"`
	RequestHash string `json:"request_hash"`
}

// Verify accepts a base64url JSON envelope. Initial registration uses
// {"attestation_object":"...","client_data":"..."}; subsequent requests
// use {"assertion":"...","client_data":"..."}. client_data is the exact
// UTF-8 JSON bytes signed by the iOS client and must contain the server
// challenge and request hash.
func (v AppleAppAttestVerifier) Verify(ctx context.Context, challenge Challenge, input Submission) (VerifiedResult, error) {
	if input.Provider != AppleAppAttestProvider {
		return VerifiedResult{}, ErrUnsupportedProvider
	}
	if err := v.validateConfig(); err != nil {
		return VerifiedResult{}, err
	}
	var envelope struct {
		AttestationObject string `json:"attestation_object"`
		Assertion         string `json:"assertion"`
		ClientData        string `json:"client_data"`
	}
	if err := decodeAppleEnvelope(input.Assertion, &envelope); err != nil {
		return VerifiedResult{}, err
	}
	if envelope.AttestationObject != "" && envelope.Assertion != "" {
		return VerifiedResult{}, ErrAppleInvalidObject
	}
	if envelope.AttestationObject != "" {
		object, err := v.verifyAttestation(challenge, input, envelope.AttestationObject)
		if err != nil {
			return VerifiedResult{}, err
		}
		der, err := x509.MarshalPKIXPublicKey(object.PublicKey)
		if err != nil {
			return VerifiedResult{}, fmt.Errorf("marshal apple app attest public key: %w", err)
		}
		return VerifiedResult{Provider: input.Provider, KeyID: input.KeyID, Counter: 0, TrustLevel: "apple-app-attest-verified", PublicKeyDER: der, BundleVersion: object.BundleVersion, Environment: v.Environment}, nil
	}
	if envelope.Assertion == "" {
		return VerifiedResult{}, ErrAppleInvalidAssertion
	}
	clientData, err := decodeAppleBase64(envelope.ClientData)
	if err != nil {
		return VerifiedResult{}, ErrAppleClientData
	}
	if err := validateAppleClientData(clientData, challenge, input); err != nil {
		return VerifiedResult{}, err
	}
	if v.Keys == nil {
		return VerifiedResult{}, ErrAppleUnavailable
	}
	key, err := v.Keys.LookupAppleAppAttestKey(ctx, input.KeyID)
	if err != nil {
		return VerifiedResult{}, fmt.Errorf("lookup apple app attest key: %w", err)
	}
	publicKey, err := parseAppleP256PublicKey(key.PublicKeyDER)
	if err != nil {
		return VerifiedResult{}, ErrAppleUnavailable
	}
	assertion, err := decodeAppleAssertion(envelope.Assertion)
	if err != nil {
		return VerifiedResult{}, err
	}
	if err := validateAppleAuthenticatorData(assertion.AuthData, v.expectedRPIDHash(), v.Environment, false); err != nil {
		return VerifiedResult{}, err
	}
	counter := binary.BigEndian.Uint32(assertion.AuthData[33:37])
	if counter <= key.Counter {
		return VerifiedResult{}, ErrAppleCounterRollback
	}
	clientDataHash := sha256.Sum256(clientData)
	nonceInput := append(append([]byte{}, assertion.AuthData...), clientDataHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	if !ecdsa.VerifyASN1(publicKey, nonce[:], assertion.Signature) {
		return VerifiedResult{}, ErrAppleInvalidAssertion
	}
	return VerifiedResult{Provider: input.Provider, KeyID: input.KeyID, Counter: uint64(counter), TrustLevel: "apple-app-attest-verified", PublicKeyDER: key.PublicKeyDER, BundleVersion: key.BundleVersion, Environment: v.Environment}, nil
}

func (v AppleAppAttestVerifier) validateConfig() error {
	if v.Root == nil || strings.TrimSpace(v.TeamID) == "" || strings.TrimSpace(v.BundleID) == "" {
		return ErrAppleUnavailable
	}
	if v.Environment != "development" && v.Environment != "production" {
		return ErrAppleUnavailable
	}
	return nil
}

func (v AppleAppAttestVerifier) verifyAttestation(challenge Challenge, input Submission, encoded string) (appleAttestationObject, error) {
	raw, err := decodeAppleBase64(encoded)
	if err != nil {
		return appleAttestationObject{}, ErrAppleInvalidObject
	}
	var document map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &document); err != nil {
		return appleAttestationObject{}, ErrAppleInvalidObject
	}
	var format string
	var authData []byte
	var statement map[string]cbor.RawMessage
	if err := decodeCBORField(document, "fmt", &format); err != nil || format != "apple-appattest" || decodeCBORField(document, "authData", &authData) != nil || decodeCBORField(document, "attStmt", &statement) != nil {
		return appleAttestationObject{}, ErrAppleInvalidObject
	}
	var certificates [][]byte
	if err := decodeCBORField(statement, "x5c", &certificates); err != nil || len(certificates) < 2 {
		return appleAttestationObject{}, ErrAppleInvalidCertificate
	}
	certs := make([]*x509.Certificate, len(certificates))
	for i, der := range certificates {
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			return appleAttestationObject{}, ErrAppleInvalidCertificate
		}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: v.Root, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: v.currentTime()}); err != nil {
		return appleAttestationObject{}, fmt.Errorf("%w: %v", ErrAppleInvalidCertificate, err)
	}
	certificateKey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || certificateKey.Curve != elliptic.P256() {
		return appleAttestationObject{}, ErrAppleInvalidCertificate
	}
	if err := validateAppleAuthenticatorData(authData, v.expectedRPIDHash(), v.Environment, true); err != nil {
		return appleAttestationObject{}, err
	}
	if len(authData) < 55 {
		return appleAttestationObject{}, ErrAppleInvalidObject
	}
	credentialLength := int(binary.BigEndian.Uint16(authData[53:55]))
	if credentialLength != 32 || len(authData) < 55+credentialLength {
		return appleAttestationObject{}, ErrAppleInvalidCredential
	}
	credential := append([]byte(nil), authData[55:55+credentialLength]...)
	if input.KeyID == "" || !constantTimeEqual(credential, []byte(input.KeyID)) {
		// App Attest key IDs are normally sent as base64; accept only the
		// decoded 32-byte representation, never an arbitrary caller string.
		decodedKey, decodeErr := decodeAppleBase64(input.KeyID)
		if decodeErr != nil || !constantTimeEqual(credential, decodedKey) {
			return appleAttestationObject{}, ErrAppleInvalidCredential
		}
	}
	keyHash := sha256.Sum256(elliptic.Marshal(elliptic.P256(), certificateKey.X, certificateKey.Y))
	if !constantTimeEqual(credential, keyHash[:]) {
		return appleAttestationObject{}, ErrAppleInvalidCredential
	}
	publicKey, extensions, err := parseAppleAttestedCredential(authData, 55+credentialLength)
	if err != nil {
		return appleAttestationObject{}, err
	}
	if publicKey.X.Cmp(certificateKey.X) != 0 || publicKey.Y.Cmp(certificateKey.Y) != 0 {
		return appleAttestationObject{}, ErrAppleInvalidCredential
	}
	clientDataHash := sha256.Sum256([]byte(challenge.Value))
	nonceInput := append(append([]byte{}, authData...), clientDataHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	if !appleCertificateNonceMatches(certs[0], nonce[:]) {
		return appleAttestationObject{}, ErrAppleInvalidNonce
	}
	bundleVersion, err := appleBundleVersion(extensions)
	if err != nil {
		return appleAttestationObject{}, err
	}
	if err := appleValidationCategory(extensions); err != nil {
		return appleAttestationObject{}, err
	}
	return appleAttestationObject{Format: format, AuthData: authData, LeafCert: certs[0], Chain: certs[1:], Credential: credential, PublicKey: publicKey, BundleVersion: bundleVersion}, nil
}

func validateAppleAuthenticatorData(data []byte, expectedRPID []byte, environment string, attestation bool) error {
	if len(data) < 37 || !constantTimeEqual(data[:32], expectedRPID) {
		return ErrAppleInvalidAppID
	}
	if attestation && binary.BigEndian.Uint32(data[33:37]) != 0 {
		return ErrAppleInvalidObject
	}
	if !attestation && binary.BigEndian.Uint32(data[33:37]) == 0 {
		return ErrAppleInvalidAssertion
	}
	if attestation && len(data) < 53 {
		return ErrAppleInvalidObject
	}
	if attestation {
		aaguid := string(data[37:53])
		if environment == "development" && aaguid != "appattestdevelop" {
			return ErrAppleInvalidEnvironment
		}
		if environment == "production" && aaguid != "appattest"+strings.Repeat("\x00", 7) {
			return ErrAppleInvalidEnvironment
		}
	}
	return nil
}

func (v AppleAppAttestVerifier) expectedRPIDHash() []byte {
	sum := sha256.Sum256([]byte(v.TeamID + "." + v.BundleID))
	return sum[:]
}

func (v AppleAppAttestVerifier) currentTime() time.Time {
	if v.Clock != nil {
		return v.Clock()
	}
	return time.Now()
}

func decodeAppleAssertion(value string) (appleAssertionObject, error) {
	raw, err := decodeAppleBase64(value)
	if err != nil {
		return appleAssertionObject{}, ErrAppleInvalidAssertion
	}
	var document map[string]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &document); err != nil {
		return appleAssertionObject{}, ErrAppleInvalidAssertion
	}
	var object appleAssertionObject
	if decodeCBORField(document, "signature", &object.Signature) != nil || decodeCBORField(document, "authenticatorData", &object.AuthData) != nil || len(object.Signature) == 0 {
		return appleAssertionObject{}, ErrAppleInvalidAssertion
	}
	return object, nil
}

func decodeAppleEnvelope(value string, destination any) error {
	raw, err := decodeAppleBase64(value)
	if err != nil || json.Unmarshal(raw, destination) != nil {
		return ErrAppleInvalidObject
	}
	return nil
}

func decodeAppleBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty base64 value")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func decodeCBORField(document map[string]cbor.RawMessage, key string, destination any) error {
	raw, ok := document[key]
	if !ok {
		return errors.New("missing cbor field")
	}
	return cbor.Unmarshal(raw, destination)
}

func validateAppleClientData(raw []byte, challenge Challenge, input Submission) error {
	var data appleClientData
	if json.Unmarshal(raw, &data) != nil || data.Challenge == "" || data.RequestHash == "" || data.Challenge != challenge.Value || data.RequestHash != input.RequestHash || data.RequestHash != challenge.RequestHash {
		return ErrAppleClientData
	}
	return nil
}

func parseAppleP256PublicKey(der []byte) (*ecdsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 public key")
	}
	return public, nil
}

func appleCertificateNonceMatches(cert *x509.Certificate, expected []byte) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(appleCredentialExtensionOID) {
			var sequence asn1.RawValue
			if _, err := asn1.Unmarshal(extension.Value, &sequence); err != nil || sequence.Tag != 16 {
				return false
			}
			var value []byte
			if _, err := asn1.Unmarshal(sequence.Bytes, &value); err != nil {
				return false
			}
			return constantTimeEqual(value, expected)
		}
	}
	return false
}

func parseAppleAttestedCredential(data []byte, offset int) (*ecdsa.PublicKey, map[string]cbor.RawMessage, error) {
	if offset >= len(data) {
		return nil, nil, ErrAppleInvalidObject
	}
	var cose map[int]cbor.RawMessage
	rest, err := cbor.UnmarshalFirst(data[offset:], &cose)
	if err != nil {
		return nil, nil, ErrAppleInvalidObject
	}
	var keyType, algorithm, curve int
	if err := decodeCBORIntField(cose, 1, &keyType); err != nil {
		return nil, nil, ErrAppleInvalidCredential
	}
	if err := decodeCBORIntField(cose, 3, &algorithm); err != nil {
		return nil, nil, ErrAppleInvalidCredential
	}
	if err := decodeCBORIntField(cose, -1, &curve); err != nil || keyType != 2 || algorithm != -7 || curve != 1 {
		return nil, nil, ErrAppleInvalidCredential
	}
	var x, y []byte
	if err := decodeCBORIntField(cose, -2, &x); err != nil {
		return nil, nil, ErrAppleInvalidCredential
	}
	if err := decodeCBORIntField(cose, -3, &y); err != nil || len(x) != 32 || len(y) != 32 {
		return nil, nil, ErrAppleInvalidCredential
	}
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, nil, ErrAppleInvalidCredential
	}
	if len(rest) == 0 {
		return publicKey, nil, nil
	}
	var extensions map[string]cbor.RawMessage
	if err := cbor.Unmarshal(rest, &extensions); err != nil {
		return nil, nil, ErrAppleInvalidObject
	}
	return publicKey, extensions, nil
}

func decodeCBORIntField(document map[int]cbor.RawMessage, key int, destination any) error {
	raw, ok := document[key]
	if !ok {
		return errors.New("missing cbor integer field")
	}
	return cbor.Unmarshal(raw, destination)
}

func appleBundleVersion(extensions map[string]cbor.RawMessage) (string, error) {
	const bundleVersionKey = "apple_bundle_version_01"
	var version string
	raw, ok := extensions[bundleVersionKey]
	if !ok || cbor.Unmarshal(raw, &version) != nil || version == "" {
		return "", ErrAppleInvalidObject
	}
	return version, nil
}

func appleValidationCategory(extensions map[string]cbor.RawMessage) error {
	const validationCategoryKey = "apple_validation_category_01"
	raw, ok := extensions[validationCategoryKey]
	if !ok {
		return ErrAppleInvalidObject
	}
	var category []byte
	if err := cbor.Unmarshal(raw, &category); err != nil || len(category) != 4 || binary.LittleEndian.Uint32(category) != 1 {
		return ErrAppleInvalidObject
	}
	return nil
}

func constantTimeEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

var _ = big.NewInt
