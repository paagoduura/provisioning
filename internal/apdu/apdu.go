// Package apdu provides transport-independent ISO/IEC 7816-4 command and
// response APDU encoding and parsing primitives.
//
// The package deliberately does not implement a card transport, GlobalPlatform,
// secure messaging, or payment application semantics. Those layers must be
// supplied by a device-specific adapter and must use an approved secure
// channel before sending sensitive commands.
package apdu

import (
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	HeaderLength            = 4
	ShortDataMaximum        = 255
	ExtendedDataMaximum     = 65535
	ShortMaximumResponse    = 256
	ExtendedMaximumResponse = 65536
)

var (
	ErrInvalidLength      = errors.New("invalid APDU length")
	ErrInvalidHeader      = errors.New("invalid APDU header")
	ErrInvalidDataLength  = errors.New("invalid APDU data length")
	ErrInvalidResponse    = errors.New("invalid APDU response")
	ErrResponseTooShort   = errors.New("APDU response is shorter than SW1/SW2")
	ErrUnexpectedTrailing = errors.New("unexpected trailing APDU bytes")
)

// Command is an ISO/IEC 7816-4 command APDU.
//
// Le is nil when no expected response length is requested. When non-nil, Le
// must be in the inclusive range 1..65536. A value of 256 or 65536 is encoded
// using the ISO short or extended zero-length convention respectively.
// Extended requests are selected automatically when required, or explicitly
// with Extended=true. Extended=true is useful when a caller needs an extended
// APDU even though its data and Le would fit in short form.
type Command struct {
	CLA byte
	INS byte
	P1  byte
	P2  byte

	Data     []byte
	Le       *uint32
	Extended bool
}

// NewCommand constructs a command and defensively copies data.
func NewCommand(cla, ins, p1, p2 byte, data []byte, le *uint32) Command {
	return Command{CLA: cla, INS: ins, P1: p1, P2: p2, Data: clone(data), Le: cloneUint32(le)}
}

// Encode serializes the command according to ISO/IEC 7816-4 short or extended
// length rules.
func (c Command) Encode() ([]byte, error) {
	if len(c.Data) > ExtendedDataMaximum {
		return nil, fmt.Errorf("%w: data length %d exceeds %d", ErrInvalidDataLength, len(c.Data), ExtendedDataMaximum)
	}
	if c.Le != nil && (*c.Le == 0 || *c.Le > ExtendedMaximumResponse) {
		return nil, fmt.Errorf("%w: Le %d must be between 1 and %d", ErrInvalidLength, *c.Le, ExtendedMaximumResponse)
	}
	if len(c.Data) == 0 && c.Le == nil {
		return []byte{c.CLA, c.INS, c.P1, c.P2}, nil
	}

	extended := c.Extended || len(c.Data) > ShortDataMaximum || (c.Le != nil && *c.Le > ShortMaximumResponse)
	if !extended {
		return c.encodeShort()
	}
	return c.encodeExtended()
}

func (c Command) encodeShort() ([]byte, error) {
	if len(c.Data) > ShortDataMaximum {
		return nil, fmt.Errorf("%w: short APDU data length %d exceeds %d", ErrInvalidDataLength, len(c.Data), ShortDataMaximum)
	}
	if c.Le != nil && *c.Le > ShortMaximumResponse {
		return nil, fmt.Errorf("%w: short APDU Le %d exceeds %d", ErrInvalidLength, *c.Le, ShortMaximumResponse)
	}

	out := []byte{c.CLA, c.INS, c.P1, c.P2}
	if len(c.Data) > 0 {
		out = append(out, byte(len(c.Data)))
		out = append(out, c.Data...)
		if c.Le != nil {
			out = append(out, encodeShortLength(*c.Le))
		}
	} else if c.Le != nil {
		out = append(out, encodeShortLength(*c.Le))
	}
	return out, nil
}

func (c Command) encodeExtended() ([]byte, error) {
	if len(c.Data) == 0 && c.Le == nil {
		return []byte{c.CLA, c.INS, c.P1, c.P2}, nil
	}

	out := []byte{c.CLA, c.INS, c.P1, c.P2}
	if len(c.Data) == 0 {
		// Extended Case 2: 00 LeHi LeLo.
		out = append(out, 0)
		out = append(out, encodeExtendedLength(*c.Le)...)
		return out, nil
	}

	// Extended Case 3/4: 00 LcHi LcLo Data [LeHi LeLo].
	out = append(out, 0, byte(len(c.Data)>>8), byte(len(c.Data)))
	out = append(out, c.Data...)
	if c.Le != nil {
		out = append(out, encodeExtendedLength(*c.Le)...)
	}
	return out, nil
}

func encodeShortLength(length uint32) byte {
	if length == ShortMaximumResponse {
		return 0
	}
	return byte(length)
}

func encodeExtendedLength(length uint32) []byte {
	if length == ExtendedMaximumResponse {
		return []byte{0, 0}
	}
	return []byte{byte(length >> 8), byte(length)}
}

// ParseCommand parses a complete command APDU. It rejects malformed length
// fields and trailing bytes so callers cannot accidentally process an ambiguous
// command frame.
func ParseCommand(raw []byte) (Command, error) {
	if len(raw) < HeaderLength {
		return Command{}, fmt.Errorf("%w: got %d bytes, need at least %d", ErrInvalidLength, len(raw), HeaderLength)
	}
	c := Command{CLA: raw[0], INS: raw[1], P1: raw[2], P2: raw[3]}
	if len(raw) == HeaderLength {
		return c, nil
	}
	if len(raw) == HeaderLength+1 {
		le := uint32(raw[4])
		if le == 0 {
			le = ShortMaximumResponse
		}
		c.Le = &le
		return c, nil
	}

	if raw[4] != 0 {
		lc := int(raw[4])
		if len(raw) < HeaderLength+1+lc {
			return Command{}, fmt.Errorf("%w: short Lc=%d but only %d data bytes remain", ErrInvalidLength, lc, len(raw)-5)
		}
		c.Data = clone(raw[5 : 5+lc])
		remaining := raw[5+lc:]
		if len(remaining) == 0 {
			return c, nil
		}
		if len(remaining) != 1 {
			return Command{}, fmt.Errorf("%w: short APDU has %d trailing bytes after data", ErrUnexpectedTrailing, len(remaining))
		}
		le := uint32(remaining[0])
		if le == 0 {
			le = ShortMaximumResponse
		}
		c.Le = &le
		return c, nil
	}

	// A zero byte at offset 4 indicates either extended Case 2 or extended
	// Case 3/4. It must be followed by a two-byte length field.
	if len(raw) < 7 {
		return Command{}, fmt.Errorf("%w: extended APDU requires at least 7 bytes", ErrInvalidLength)
	}
	c.Extended = true
	if raw[5] == 0 && raw[6] == 0 {
		le := uint32(ExtendedMaximumResponse)
		c.Le = &le
		if len(raw) != 7 {
			return Command{}, fmt.Errorf("%w: extended Case 2 has %d trailing bytes", ErrUnexpectedTrailing, len(raw)-7)
		}
		return c, nil
	}

	lc := int(raw[5])<<8 | int(raw[6])
	if lc == 0 {
		return Command{}, fmt.Errorf("%w: extended Lc cannot be zero", ErrInvalidDataLength)
	}
	dataStart := 7
	dataEnd := dataStart + lc
	if len(raw) < dataEnd {
		return Command{}, fmt.Errorf("%w: extended Lc=%d but only %d data bytes remain", ErrInvalidLength, lc, len(raw)-dataStart)
	}
	c.Data = clone(raw[dataStart:dataEnd])
	remaining := raw[dataEnd:]
	if len(remaining) == 0 {
		return c, nil
	}
	if len(remaining) != 2 {
		return Command{}, fmt.Errorf("%w: extended APDU has %d trailing bytes after data", ErrUnexpectedTrailing, len(remaining))
	}
	le := uint32(remaining[0])<<8 | uint32(remaining[1])
	if le == 0 {
		le = ExtendedMaximumResponse
	}
	c.Le = &le
	return c, nil
}

// Response is an ISO/IEC 7816-4 response APDU. The final two bytes are SW1
// and SW2; all preceding bytes are response data.
type Response struct {
	Data []byte
	SW1  byte
	SW2  byte
}

// ParseResponse parses a complete response APDU and defensively copies data.
func ParseResponse(raw []byte) (Response, error) {
	if len(raw) < 2 {
		return Response{}, fmt.Errorf("%w: got %d bytes", ErrResponseTooShort, len(raw))
	}
	return Response{Data: clone(raw[:len(raw)-2]), SW1: raw[len(raw)-2], SW2: raw[len(raw)-1]}, nil
}

// StatusWord returns the combined SW1/SW2 status word.
func (r Response) StatusWord() uint16 { return uint16(r.SW1)<<8 | uint16(r.SW2) }

// Success reports whether the card returned the ISO success status 9000.
func (r Response) Success() bool { return r.StatusWord() == 0x9000 }

// MoreData reports a successful GET RESPONSE hint (61xx).
func (r Response) MoreData() bool { return r.SW1 == 0x61 }

// Warning reports a warning status (62xx or 63xx).
func (r Response) Warning() bool { return r.SW1 == 0x62 || r.SW1 == 0x63 }

// Error reports an error status. It intentionally treats warnings as not an
// error; callers must decide whether a warning is acceptable for their command.
func (r Response) Error() bool { return r.SW1 >= 0x64 && r.SW1 != 0x90 }

// StatusDescription provides a bounded description for common ISO status
// words. Unknown values remain explicit rather than being guessed.
func (r Response) StatusDescription() string {
	switch r.StatusWord() {
	case 0x9000:
		return "success"
	case 0x6100:
		return "more response data available"
	case 0x6283:
		return "selected file invalidated"
	case 0x6300:
		return "warning: authentication failed"
	case 0x6700:
		return "wrong length"
	case 0x6982:
		return "security status not satisfied"
	case 0x6985:
		return "conditions of use not satisfied"
	case 0x6a80:
		return "incorrect data"
	case 0x6a82:
		return "file or application not found"
	case 0x6a86:
		return "incorrect parameters"
	case 0x6d00:
		return "instruction not supported"
	case 0x6e00:
		return "class not supported"
	default:
		return fmt.Sprintf("unknown status %04X", r.StatusWord())
	}
}

// Redacted returns a diagnostic representation that never includes APDU data.
func (c Command) Redacted() string {
	le := "absent"
	if c.Le != nil {
		le = fmt.Sprintf("%d", *c.Le)
	}
	form := "short"
	if c.Extended {
		form = "extended"
	}
	return fmt.Sprintf("CLA=%02X INS=%02X P1=%02X P2=%02X data_len=%d le=%s encoding=%s", c.CLA, c.INS, c.P1, c.P2, len(c.Data), le, form)
}

// Redacted returns a diagnostic representation that never includes response data.
func (r Response) Redacted() string {
	return fmt.Sprintf("data_len=%d sw=%04X (%s)", len(r.Data), r.StatusWord(), r.StatusDescription())
}

// Hex returns a hex representation for protocol tests and controlled tooling.
// It must not be used for production logs because APDU payloads may contain
// payment or key material.
func Hex(raw []byte) string { return hex.EncodeToString(raw) }

func clone(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func cloneUint32(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
