package apdu

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func uint32ptr(v uint32) *uint32 { return &v }

func TestEncodeShortCases(t *testing.T) {
	tests := []struct {
		name string
		cmd  Command
		want []byte
	}{
		{"case1", Command{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00}, []byte{0x00, 0xA4, 0x04, 0x00}},
		{"case2", Command{CLA: 0x00, INS: 0xC0, Le: uint32ptr(10)}, []byte{0x00, 0xC0, 0x00, 0x00, 0x0A}},
		{"case2 maximum", Command{CLA: 0x00, INS: 0xC0, Le: uint32ptr(256)}, []byte{0x00, 0xC0, 0x00, 0x00, 0x00}},
		{"case3", Command{CLA: 0x80, INS: 0xDA, P1: 0x01, P2: 0x02, Data: []byte{0xDE, 0xAD}}, []byte{0x80, 0xDA, 0x01, 0x02, 0x02, 0xDE, 0xAD}},
		{"case4", Command{CLA: 0x80, INS: 0xDA, Data: []byte{0xDE, 0xAD}, Le: uint32ptr(16)}, []byte{0x80, 0xDA, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0x10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cmd.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got %X, want %X", got, tt.want)
			}
		})
	}
}

func TestEncodeExtendedCases(t *testing.T) {
	data := bytes.Repeat([]byte{0xA5}, 256)
	tests := []struct {
		name  string
		cmd   Command
		check func(t *testing.T, got []byte)
	}{
		{
			name: "extended case2 maximum",
			cmd:  Command{CLA: 0x00, INS: 0xC0, Le: uint32ptr(65536)},
			check: func(t *testing.T, got []byte) {
				want := []byte{0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00}
				if !bytes.Equal(got, want) {
					t.Fatalf("got %X, want %X", got, want)
				}
			},
		},
		{
			name: "extended case3",
			cmd:  Command{CLA: 0x80, INS: 0xE8, Data: data},
			check: func(t *testing.T, got []byte) {
				if len(got) != 7+len(data) || got[4] != 0 || got[5] != 1 || got[6] != 0 || !bytes.Equal(got[7:], data) {
					t.Fatalf("invalid extended case3: len=%d prefix=%X", len(got), got[:7])
				}
			},
		},
		{
			name: "extended case4",
			cmd:  Command{CLA: 0x80, INS: 0xE8, Data: data, Le: uint32ptr(1024)},
			check: func(t *testing.T, got []byte) {
				if len(got) != 9+len(data) || !bytes.Equal(got[len(got)-2:], []byte{0x04, 0x00}) {
					t.Fatalf("invalid extended case4: len=%d suffix=%X", len(got), got[len(got)-2:])
				}
			},
		},
		{
			name: "forced extended short payload",
			cmd:  Command{CLA: 0x00, INS: 0xA4, Extended: true, Data: []byte{0x3F, 0x00}, Le: uint32ptr(256)},
			check: func(t *testing.T, got []byte) {
				want := []byte{0x00, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x00, 0x01, 0x00}
				if !bytes.Equal(got, want) {
					t.Fatalf("got %X, want %X", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cmd.Encode()
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, got)
		})
	}
}

func TestCommandRoundTrip(t *testing.T) {
	tests := []Command{
		{CLA: 0x00, INS: 0xA4, P1: 0x04, P2: 0x00},
		{CLA: 0x00, INS: 0xC0, Le: uint32ptr(256)},
		{CLA: 0x80, INS: 0xDA, Data: []byte{1, 2, 3}},
		{CLA: 0x80, INS: 0xDA, Data: []byte{1, 2, 3}, Le: uint32ptr(255)},
		{CLA: 0x80, INS: 0xE8, Data: bytes.Repeat([]byte{0x42}, 300), Le: uint32ptr(65536)},
	}
	for _, original := range tests {
		raw, err := original.Encode()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseCommand(raw)
		if err != nil {
			t.Fatalf("parse %X: %v", raw, err)
		}
		if parsed.CLA != original.CLA || parsed.INS != original.INS || parsed.P1 != original.P1 || parsed.P2 != original.P2 || !bytes.Equal(parsed.Data, original.Data) {
			t.Fatalf("header/data mismatch: got %+v, want %+v", parsed, original)
		}
		if (parsed.Le == nil) != (original.Le == nil) || (parsed.Le != nil && *parsed.Le != *original.Le) {
			t.Fatalf("Le mismatch: got %v, want %v", parsed.Le, original.Le)
		}
	}
}

func TestParseCommandRejectsMalformedFrames(t *testing.T) {
	tests := [][]byte{
		{}, {0x00, 0xA4, 0x04},
		{0x00, 0xDA, 0x00, 0x00, 0x03, 0x01},
		{0x00, 0xDA, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03},
		{0x00, 0xDA, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0xDA, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0x00},
	}
	for _, raw := range tests {
		if _, err := ParseCommand(raw); err == nil {
			t.Fatalf("expected malformed APDU rejection for %X", raw)
		}
	}
}

func TestEncodeRejectsInvalidLengths(t *testing.T) {
	tooLarge := bytes.Repeat([]byte{0}, ExtendedDataMaximum+1)
	for _, cmd := range []Command{
		{Data: tooLarge},
		{Le: uint32ptr(0)},
		{Le: uint32ptr(ExtendedMaximumResponse + 1)},
	} {
		if _, err := cmd.Encode(); err == nil || (!errors.Is(err, ErrInvalidLength) && !errors.Is(err, ErrInvalidDataLength)) {
			t.Fatalf("expected length error, got %v", err)
		}
	}
}

func TestParseResponseAndStatus(t *testing.T) {
	response, err := ParseResponse([]byte{0xDE, 0xAD, 0x90, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Data, []byte{0xDE, 0xAD}) || !response.Success() || response.StatusWord() != 0x9000 {
		t.Fatalf("unexpected response: %+v", response)
	}
	if _, err := ParseResponse([]byte{0x90}); !errors.Is(err, ErrResponseTooShort) {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		sw                     uint16
		more, warning, failure bool
	}{
		{0x6100, true, false, false},
		{0x6283, false, true, false},
		{0x6982, false, false, true},
		{0x6D00, false, false, true},
	}
	for _, tt := range cases {
		r := Response{SW1: byte(tt.sw >> 8), SW2: byte(tt.sw)}
		if r.MoreData() != tt.more || r.Warning() != tt.warning || r.Error() != tt.failure {
			t.Fatalf("status %04X classification incorrect", tt.sw)
		}
	}
}

func TestRedactedDiagnosticsDoNotLeakPayloads(t *testing.T) {
	secret := []byte("payment-secret")
	cmd := Command{CLA: 0x80, INS: 0xE8, Data: secret, Le: uint32ptr(256)}
	text := cmd.Redacted()
	if strings.Contains(text, string(secret)) || strings.Contains(text, Hex(secret)) {
		t.Fatalf("command payload leaked: %s", text)
	}
	response := Response{Data: secret, SW1: 0x90, SW2: 0x00}
	text = response.Redacted()
	if strings.Contains(text, string(secret)) || strings.Contains(text, Hex(secret)) {
		t.Fatalf("response payload leaked: %s", text)
	}
}

func TestCommandAndResponseOwnTheirBuffers(t *testing.T) {
	data := []byte{1, 2, 3}
	cmd := NewCommand(0, 0, 0, 0, data, uint32ptr(3))
	data[0] = 9
	if cmd.Data[0] != 1 || *cmd.Le != 3 {
		t.Fatal("constructor did not copy input")
	}

	raw, err := cmd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[5] = 9
	if parsed.Data[0] != 1 {
		t.Fatal("parser did not copy input")
	}
}
