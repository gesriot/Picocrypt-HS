package header

import (
	"bytes"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

func TestHeaderSize(t *testing.T) {
	// Base header size without comments
	if HeaderSize(0) != BaseHeaderSize {
		t.Errorf("HeaderSize(0) = %d; want %d", HeaderSize(0), BaseHeaderSize)
	}

	// Header with 10 comments
	expected := BaseHeaderSize + 10*3 // Each comment byte is rs1 encoded (1->3)
	if HeaderSize(10) != expected {
		t.Errorf("HeaderSize(10) = %d; want %d", HeaderSize(10), expected)
	}

	// Verify base header size calculation
	// 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192 = 789
	expectedBase := 15 + 15 + 15 + 48 + 96 + 48 + 72 + 192 + 96 + 192
	if BaseHeaderSize != expectedBase {
		t.Errorf("BaseHeaderSize = %d; want %d", BaseHeaderSize, expectedBase)
	}
}

func TestFlags(t *testing.T) {
	// Test all flags set
	flags := Flags{
		Paranoid:       true,
		UseKeyfiles:    true,
		KeyfileOrdered: true,
		ReedSolomon:    true,
		Padded:         true,
	}

	b := flags.ToBytes()
	if len(b) != 5 {
		t.Fatalf("ToBytes() length = %d; want 5", len(b))
	}

	for i := range 5 {
		if b[i] != 1 {
			t.Errorf("ToBytes()[%d] = %d; want 1", i, b[i])
		}
	}

	// Round-trip
	parsed := FlagsFromBytes(b)
	if !parsed.Paranoid || !parsed.UseKeyfiles || !parsed.KeyfileOrdered ||
		!parsed.ReedSolomon || !parsed.Padded {
		t.Error("FlagsFromBytes did not preserve all flags")
	}

	// Test no flags set
	flags = Flags{}
	b = flags.ToBytes()
	for i := range 5 {
		if b[i] != 0 {
			t.Errorf("Empty flags ToBytes()[%d] = %d; want 0", i, b[i])
		}
	}
}

func TestFlagsFromBytesShort(t *testing.T) {
	// Should handle short/nil input gracefully
	flags := FlagsFromBytes(nil)
	if flags.Paranoid || flags.UseKeyfiles || flags.KeyfileOrdered ||
		flags.ReedSolomon || flags.Padded {
		t.Error("FlagsFromBytes(nil) should return empty flags")
	}

	flags = FlagsFromBytes([]byte{1, 1}) // Only 2 bytes
	if flags.Paranoid || flags.UseKeyfiles {
		t.Error("FlagsFromBytes with short input should return empty flags")
	}
}

func TestNewVolumeHeader(t *testing.T) {
	salt := make([]byte, SaltSize)
	hkdfSalt := make([]byte, HKDFSaltSize)
	serpentIV := make([]byte, SerpentIVSize)
	nonce := make([]byte, NonceSize)

	h := NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)

	if h.Version != CurrentVersion {
		t.Errorf("Version = %s; want %s", h.Version, CurrentVersion)
	}

	if len(h.Salt) != SaltSize {
		t.Errorf("Salt length = %d; want %d", len(h.Salt), SaltSize)
	}

	if len(h.KeyHash) != KeyHashSize {
		t.Errorf("KeyHash length = %d; want %d", len(h.KeyHash), KeyHashSize)
	}

	if len(h.KeyfileHash) != KeyfileHashSize {
		t.Errorf("KeyfileHash length = %d; want %d", len(h.KeyfileHash), KeyfileHashSize)
	}

	if len(h.AuthTag) != AuthTagSize {
		t.Errorf("AuthTag length = %d; want %d", len(h.AuthTag), AuthTagSize)
	}
}

func TestIsLegacyV1(t *testing.T) {
	tests := []struct {
		version  string
		expected bool
	}{
		{"v2.00", false},
		{"v2.02", false},
		{"v1.00", true},
		{"v1.34", true},
		{"v1.99", true},
		{"", false},
		{"v", false},
	}

	for _, tc := range tests {
		h := &VolumeHeader{Version: tc.version}
		if h.IsLegacyV1() != tc.expected {
			t.Errorf("IsLegacyV1(%q) = %v; want %v", tc.version, h.IsLegacyV1(), tc.expected)
		}
	}
}

func TestNewCodecs(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	codecs := NewCodecs(rs)
	if codecs.RSCodecs != rs {
		t.Error("NewCodecs did not wrap RSCodecs correctly")
	}
}

func TestHeaderWriteReadRoundtrip(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Create a header with known values
	original := &VolumeHeader{
		Version:  CurrentVersion,
		Comments: "Test comment",
		Flags: Flags{
			Paranoid:       true,
			UseKeyfiles:    true,
			KeyfileOrdered: false,
			ReedSolomon:    true,
			Padded:         false,
		},
		Salt:        bytes.Repeat([]byte{0x01}, SaltSize),
		HKDFSalt:    bytes.Repeat([]byte{0x02}, HKDFSaltSize),
		SerpentIV:   bytes.Repeat([]byte{0x03}, SerpentIVSize),
		Nonce:       bytes.Repeat([]byte{0x04}, NonceSize),
		KeyHash:     bytes.Repeat([]byte{0x05}, KeyHashSize),
		KeyfileHash: bytes.Repeat([]byte{0x06}, KeyfileHashSize),
		AuthTag:     bytes.Repeat([]byte{0x07}, AuthTagSize),
	}

	// Write header
	var buf bytes.Buffer
	writer := NewWriter(&buf, rs)
	n, err := writer.WriteHeader(original)
	if err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}

	expectedSize := HeaderSize(len(original.Comments))
	if n != expectedSize {
		t.Errorf("WriteHeader wrote %d bytes; want %d", n, expectedSize)
	}

	// Read header back
	reader := NewReader(&buf, rs)
	result, err := reader.ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if result.DecodeError != nil {
		t.Errorf("ReadHeader had decode errors: %v", result.DecodeError)
	}

	// Compare fields
	parsed := result.Header
	if parsed.Version != original.Version {
		t.Errorf("Version = %s; want %s", parsed.Version, original.Version)
	}

	if parsed.Comments != original.Comments {
		t.Errorf("Comments = %s; want %s", parsed.Comments, original.Comments)
	}

	if parsed.Flags.Paranoid != original.Flags.Paranoid {
		t.Errorf("Paranoid = %v; want %v", parsed.Flags.Paranoid, original.Flags.Paranoid)
	}

	if !bytes.Equal(parsed.Salt, original.Salt) {
		t.Error("Salt mismatch")
	}

	if !bytes.Equal(parsed.HKDFSalt, original.HKDFSalt) {
		t.Error("HKDFSalt mismatch")
	}

	if !bytes.Equal(parsed.SerpentIV, original.SerpentIV) {
		t.Error("SerpentIV mismatch")
	}

	if !bytes.Equal(parsed.Nonce, original.Nonce) {
		t.Error("Nonce mismatch")
	}
}
