// Package globalplatform provides validated GlobalPlatform card-manager command
// builders on top of the transport-independent apdu package.
//
// This package does not implement a card transport, secure messaging, payment
// applets, key storage, or vendor-specific personalization. Commands carrying
// sensitive material must be sent only after the caller establishes the
// approved SCP03/SCP11 channel for the target card profile.
package globalplatform

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/paagoduura/provisioning/internal/apdu"
)

const (
	CardManagerCLA byte = 0x80
	ISOCLA         byte = 0x00

	INSSelect               byte = 0xA4
	INSGetData              byte = 0xCA
	INSGetStatus            byte = 0xF2
	INSInitializeUpdate     byte = 0x50
	INSExternalAuthenticate byte = 0x82
	INSInstall              byte = 0xE6
	INSLoad                 byte = 0xE8
	INSMakeSelectable       byte = 0xE6
	INSSetStatus            byte = 0xF0
	INSDelete               byte = 0xE4

	InstallP1ForLoad           byte = 0x02
	InstallP1ForInstall        byte = 0x04
	InstallP1ForMakeSelectable byte = 0x08

	// SecurityLevel values are the GlobalPlatform secure-messaging level bits.
	SecurityLevelCENC byte = 0x02
	SecurityLevelCMAC byte = 0x01
	SecurityLevelRENC byte = 0x10
	SecurityLevelRMAC byte = 0x20
)

var (
	ErrInvalidAID              = errors.New("invalid GlobalPlatform AID")
	ErrInvalidChallenge        = errors.New("invalid GlobalPlatform host challenge")
	ErrInvalidCryptogram       = errors.New("invalid GlobalPlatform cryptogram")
	ErrInvalidSecurityLevel    = errors.New("invalid GlobalPlatform security level")
	ErrInvalidTag              = errors.New("invalid GlobalPlatform data tag")
	ErrInvalidCommandData      = errors.New("invalid GlobalPlatform command data")
	ErrInvalidBlockNumber      = errors.New("invalid GlobalPlatform load block number")
	ErrInvalidStatusParameters = errors.New("invalid GlobalPlatform status parameters")
)

// AID is an ISO/IEC 7816 application identifier. GlobalPlatform AIDs are 5 to
// 16 bytes long.
type AID []byte

// NewAID validates and defensively copies an AID.
func NewAID(value []byte) (AID, error) {
	if err := validateAID(value); err != nil {
		return nil, err
	}
	return AID(append([]byte(nil), value...)), nil
}

// ParseAIDHex parses a hexadecimal AID without accepting separators or a 0x
// prefix. This keeps configuration unambiguous and avoids silently changing an
// identifier supplied by a card or vendor profile.
func ParseAIDHex(value string) (AID, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAID, err)
	}
	return NewAID(decoded)
}

func validateAID(value []byte) error {
	if len(value) < 5 || len(value) > 16 {
		return fmt.Errorf("%w: length %d is outside 5..16 bytes", ErrInvalidAID, len(value))
	}
	return nil
}

func copyAID(value AID) []byte { return append([]byte(nil), value...) }

func responseLength() *uint32 {
	value := uint32(apdu.ShortMaximumResponse)
	return &value
}

// Select returns an ISO SELECT-by-AID command for an application or security
// domain. The caller must decide whether the returned response is acceptable
// for the target card profile.
func Select(aid AID) (apdu.Command, error) {
	if err := validateAID(aid); err != nil {
		return apdu.Command{}, err
	}
	return apdu.NewCommand(ISOCLA, INSSelect, 0x04, 0x00, copyAID(aid), responseLength()), nil
}

// GetData returns a GlobalPlatform GET DATA command for a two-byte tag.
func GetData(tag uint16) (apdu.Command, error) {
	if tag == 0 {
		return apdu.Command{}, fmt.Errorf("%w: tag cannot be 0000", ErrInvalidTag)
	}
	return apdu.NewCommand(CardManagerCLA, INSGetData, byte(tag>>8), byte(tag), nil, responseLength()), nil
}

// GetStatus returns a profile-controlled GET STATUS command. The caller must
// provide the search data specified by the approved GlobalPlatform/card profile
// rather than relying on a guessed application identifier layout.
func GetStatus(p1, p2 byte, searchData []byte) (apdu.Command, error) {
	if len(searchData) > apdu.ShortDataMaximum {
		return apdu.Command{}, fmt.Errorf("%w: search data exceeds short APDU capacity", ErrInvalidStatusParameters)
	}
	return apdu.NewCommand(CardManagerCLA, INSGetStatus, p1, p2, searchData, responseLength()), nil
}

// InitializeUpdate constructs the SCP initialization command. The host
// challenge is exactly eight bytes for the GlobalPlatform SCP03 exchange. The
// key version and key identifier are encoded in P1/P2 and are therefore
// selected by the approved card profile, not guessed by this package.
func InitializeUpdate(keyVersion, keyIdentifier byte, hostChallenge [8]byte) apdu.Command {
	return apdu.NewCommand(CardManagerCLA, INSInitializeUpdate, keyVersion, keyIdentifier, hostChallenge[:], responseLength())
}

// ExternalAuthenticate constructs the GlobalPlatform external-authentication
// command. The caller supplies the cryptogram produced by its approved SCP
// implementation; this package does not derive or store keys.
func ExternalAuthenticate(securityLevel byte, hostCryptogram []byte) (apdu.Command, error) {
	if securityLevel&^(SecurityLevelCENC|SecurityLevelCMAC|SecurityLevelRENC|SecurityLevelRMAC) != 0 || securityLevel == 0 {
		return apdu.Command{}, fmt.Errorf("%w: %02X", ErrInvalidSecurityLevel, securityLevel)
	}
	if len(hostCryptogram) != 8 {
		return apdu.Command{}, fmt.Errorf("%w: got %d bytes, want 8", ErrInvalidCryptogram, len(hostCryptogram))
	}
	return apdu.NewCommand(0x84, INSExternalAuthenticate, securityLevel, 0x00, hostCryptogram, nil), nil
}

// InstallForLoadData is the standard length-prefixed data portion for
// INSTALL [for load]. Optional AIDs are represented by an empty field only
// where the profile explicitly permits an empty value.
type InstallForLoadData struct {
	LoadFileAID       AID
	SecurityDomainAID AID
	LoadFileData      []byte
	LoadToken         []byte
}

// InstallForLoad constructs INSTALL [for load]. The data fields use the
// GlobalPlatform one-byte-length encoding and are bounded to a short APDU.
func InstallForLoad(request InstallForLoadData) (apdu.Command, error) {
	if err := validateAID(request.LoadFileAID); err != nil {
		return apdu.Command{}, fmt.Errorf("load file AID: %w", err)
	}
	if len(request.SecurityDomainAID) > 0 {
		if err := validateAID(request.SecurityDomainAID); err != nil {
			return apdu.Command{}, fmt.Errorf("security domain AID: %w", err)
		}
	}
	data, err := encodeLengthPrefixedFields([][]byte{request.LoadFileAID, request.SecurityDomainAID, request.LoadFileData, request.LoadToken})
	if err != nil {
		return apdu.Command{}, err
	}
	return apdu.NewCommand(CardManagerCLA, INSInstall, InstallP1ForLoad, 0x00, data, nil), nil
}

// Load constructs one GlobalPlatform LOAD block. Block numbers are one-based
// and the final-block bit is represented by P2 bit 0x80. The caller supplies a
// block that has already been encrypted/MACed by the approved secure-channel
// implementation.
func Load(blockNumber byte, final bool, block []byte) (apdu.Command, error) {
	if blockNumber == 0 {
		return apdu.Command{}, fmt.Errorf("%w: block numbers are one-based", ErrInvalidBlockNumber)
	}
	if len(block) == 0 || len(block) > apdu.ExtendedDataMaximum {
		return apdu.Command{}, fmt.Errorf("%w: block length %d", ErrInvalidCommandData, len(block))
	}
	p2 := byte(0)
	if final {
		p2 = 0x80
	}
	return apdu.NewCommand(CardManagerCLA, INSLoad, blockNumber, p2, block, nil), nil
}

func encodeLengthPrefixedFields(fields [][]byte) ([]byte, error) {
	var total int
	for _, field := range fields {
		if len(field) > 255 {
			return nil, fmt.Errorf("%w: field length %d exceeds one-byte length", ErrInvalidCommandData, len(field))
		}
		total += 1 + len(field)
	}
	if total > apdu.ShortDataMaximum {
		return nil, fmt.Errorf("%w: encoded fields length %d exceeds short APDU capacity", ErrInvalidCommandData, total)
	}
	data := make([]byte, 0, total)
	for _, field := range fields {
		data = append(data, byte(len(field)))
		data = append(data, field...)
	}
	return data, nil
}
