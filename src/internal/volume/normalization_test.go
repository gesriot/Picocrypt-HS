package volume

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// decomposedPassword is "é" in NFD (U+0065 U+0301), built from explicit code
// points so the source literal cannot be silently re-composed by an editor.
// wantNFCBytes is its NFC UTF-8 encoding (U+00E9) — the UAX #15 worked vector
// behind issue #19: the same visible password in two byte forms.
var (
	decomposedPassword = string([]rune{0x0065, 0x0301})
	wantNFCBytes       = []byte{0xc3, 0xa9}
)

// captureKDF installs a KDF hook that records the password bytes handed to the
// volume / deniability key derivation, while still producing a real (fast,
// byte-sensitive) key so the surrounding encrypt/decrypt logic runs normally.
// The returned restore func reverts the hooks.
func captureKDF(volumePW, deniabilityPW *[]byte) func() {
	return useTestKDF(
		func(pw, salt []byte, paranoid bool) ([]byte, error) {
			if volumePW != nil {
				*volumePW = append([]byte(nil), pw...)
			}
			return fastTestVolumeKey(pw, salt, paranoid)
		},
		func(pw, salt []byte) []byte {
			if deniabilityPW != nil {
				*deniabilityPW = append([]byte(nil), pw...)
			}
			return fastTestDeniabilityKey(pw, salt)
		},
	)
}

func writeTempInput(t *testing.T) string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "pt.txt")
	if err := os.WriteFile(in, []byte("plaintext"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return in
}

// TestEncryptNormalizesPasswordToNFC asserts the encrypt path feeds the KDF the
// NFC form of the password, so a volume created from a decomposed (e.g. macOS)
// password is byte-identical to one created from the composed form — the core
// of the #19 fix. Before normalization the KDF would see the raw NFD bytes and
// this fails.
func TestEncryptNormalizesPasswordToNFC(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	in := writeTempInput(t)
	out := filepath.Join(filepath.Dir(in), "v.txt.pcv")

	var fedToKDF []byte
	restore := captureKDF(&fedToKDF, nil)
	defer restore()

	req := &EncryptRequest{
		InputFile:  in,
		OutputFile: out,
		Password:   decomposedPassword,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}
	if err := Encrypt(context.Background(), req); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !bytes.Equal(fedToKDF, wantNFCBytes) {
		t.Errorf("encrypt fed KDF % x, want NFC % x", fedToKDF, wantNFCBytes)
	}
}

// TestEncryptDeniabilityNormalizesPasswordToNFC asserts BOTH the inner volume
// key and the outer deniability-wrapper key are derived from the NFC form, so a
// deniable volume is cross-platform-decryptable too (the deniability layer has
// no readable header, so it relies entirely on a canonical password).
func TestEncryptDeniabilityNormalizesPasswordToNFC(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("RS codecs: %v", err)
	}
	in := writeTempInput(t)
	out := filepath.Join(filepath.Dir(in), "v.txt.pcv")

	var fedToVolume, fedToDeniability []byte
	restore := captureKDF(&fedToVolume, &fedToDeniability)
	defer restore()

	req := &EncryptRequest{
		InputFile:   in,
		OutputFile:  out,
		Password:    decomposedPassword,
		Deniability: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rsCodecs,
	}
	if err := Encrypt(context.Background(), req); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if !bytes.Equal(fedToVolume, wantNFCBytes) {
		t.Errorf("inner volume key fed KDF % x, want NFC % x", fedToVolume, wantNFCBytes)
	}
	if !bytes.Equal(fedToDeniability, wantNFCBytes) {
		t.Errorf("deniability wrapper fed KDF % x, want NFC % x", fedToDeniability, wantNFCBytes)
	}
}
