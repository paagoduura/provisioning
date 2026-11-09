package globalplatform

import (
	"bytes"
	"errors"
	"testing"

	"github.com/paagoduura/provisioning/internal/apdu"
)

func aid(t *testing.T, value ...byte) AID {
	t.Helper()
	result, err := NewAID(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAIDValidationAndParsing(t *testing.T) {
	for _, length := range []int{0, 4, 17} {
		value := make([]byte, length)
		if _, err := NewAID(value); !errors.Is(err, ErrInvalidAID) {
			t.Fatalf("length %d: got %v", length, err)
		}
	}
	parsed, err := ParseAIDHex("A0000000031010")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, []byte{0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}) {
		t.Fatalf("unexpected AID %X", parsed)
	}
	if _, err := ParseAIDHex("0xA0000000031010"); !errors.Is(err, ErrInvalidAID) {
		t.Fatalf("expected strict hex rejection, got %v", err)
	}
}

func TestSelect(t *testing.T) {
	command, err := Select(aid(t, 0xA0, 0x00, 0x00, 0x00, 0x03))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := command.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00}
	if !bytes.Equal(raw, want) {
		t.Fatalf("got %X, want %X", raw, want)
	}
}

func TestGetDataAndGetStatus(t *testing.T) {
	getData, err := GetData(0x0066)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := getData.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x80, 0xCA, 0x00, 0x66, 0x00}) {
		t.Fatalf("GET DATA: got %X", raw)
	}

	getStatus, err := GetStatus(0x40, 0x00, []byte{0x4F, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = getStatus.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x80, 0xF2, 0x40, 0x00, 0x02, 0x4F, 0x00, 0x00}) {
		t.Fatalf("GET STATUS: got %X", raw)
	}
}

func TestInitializeUpdateAndExternalAuthenticate(t *testing.T) {
	challenge := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	initialize := InitializeUpdate(0x01, 0x02, challenge)
	raw, err := initialize.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x80, 0x50, 0x01, 0x02, 0x08, 0, 1, 2, 3, 4, 5, 6, 7, 0}) {
		t.Fatalf("INITIALIZE UPDATE: got %X", raw)
	}

	cryptogram := bytes.Repeat([]byte{0xCC}, 8)
	external, err := ExternalAuthenticate(SecurityLevelCMAC|SecurityLevelCENC, cryptogram)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = external.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, append([]byte{0x84, 0x82, 0x03, 0x00, 0x08}, cryptogram...)) {
		t.Fatalf("EXTERNAL AUTHENTICATE: got %X", raw)
	}
}

func TestInstallForLoadAndLoad(t *testing.T) {
	request := InstallForLoadData{
		LoadFileAID:       aid(t, 0xA0, 0, 0, 0, 1),
		SecurityDomainAID: aid(t, 0xA0, 0, 0, 0, 2),
		LoadFileData:      []byte{0x01, 0x02},
		LoadToken:         []byte{0x03},
	}
	install, err := InstallForLoad(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := install.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x80, 0xE6, 0x02, 0x00, 0x11, 0x05, 0xA0, 0, 0, 0, 1, 0x05, 0xA0, 0, 0, 0, 2, 0x02, 1, 2, 0x01, 3}
	if !bytes.Equal(raw, want) {
		t.Fatalf("INSTALL FOR LOAD: got %X, want %X", raw, want)
	}

	block, err := Load(1, true, []byte{0xDE, 0xAD})
	if err != nil {
		t.Fatal(err)
	}
	raw, err = block.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{0x80, 0xE8, 0x01, 0x80, 0x02, 0xDE, 0xAD}) {
		t.Fatalf("LOAD: got %X", raw)
	}
}

func TestGlobalPlatformValidation(t *testing.T) {
	if _, err := Select(AID{1, 2, 3}); !errors.Is(err, ErrInvalidAID) {
		t.Fatalf("SELECT invalid AID: %v", err)
	}
	if _, err := GetData(0); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("GET DATA invalid tag: %v", err)
	}
	if _, err := GetStatus(0, 0, bytes.Repeat([]byte{0}, 256)); !errors.Is(err, ErrInvalidStatusParameters) {
		t.Fatalf("GET STATUS oversized data: %v", err)
	}
	if _, err := ExternalAuthenticate(0, bytes.Repeat([]byte{0}, 8)); !errors.Is(err, ErrInvalidSecurityLevel) {
		t.Fatalf("invalid security level: %v", err)
	}
	if _, err := ExternalAuthenticate(SecurityLevelCMAC, bytes.Repeat([]byte{0}, 7)); !errors.Is(err, ErrInvalidCryptogram) {
		t.Fatalf("invalid cryptogram: %v", err)
	}
	if _, err := Load(0, false, []byte{1}); !errors.Is(err, ErrInvalidBlockNumber) {
		t.Fatalf("invalid block number: %v", err)
	}
	if _, err := Load(1, false, nil); !errors.Is(err, ErrInvalidCommandData) {
		t.Fatalf("empty load block: %v", err)
	}
}

func TestAIDAndInputBuffersAreCopied(t *testing.T) {
	value := []byte{1, 2, 3, 4, 5}
	parsed, err := NewAID(value)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 9
	if parsed[0] != 1 {
		t.Fatal("AID was not copied")
	}

	block := []byte{1, 2, 3}
	command, err := Load(1, false, block)
	if err != nil {
		t.Fatal(err)
	}
	block[0] = 9
	if command.Data[0] != 1 {
		t.Fatal("command data was not copied")
	}
}

func TestCommandsRemainParseableByAPDUFoundation(t *testing.T) {
	command, err := Select(aid(t, 0xA0, 0, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := command.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := apdu.ParseCommand(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.CLA != 0 || parsed.INS != INSSelect || !bytes.Equal(parsed.Data, []byte{0xA0, 0, 0, 0, 1}) {
		t.Fatalf("unexpected parsed command: %+v", parsed)
	}
}
