package wasm

import (
	"bytes"
	"testing"
)

// Built from explicit code points so the source literal cannot be silently
// re-normalized: nfdPassword is "é" decomposed (U+0065 U+0301), nfcPassword is
// the composed form (U+00E9). Same visible password, different bytes.
var (
	nfdPassword = string([]rune{0x0065, 0x0301})
	nfcPassword = string([]rune{0x00E9})
)

// TestWASMEncryptNormalizesPassword proves the web build normalizes the
// password to NFC on encrypt: a volume created with the decomposed form must
// decrypt with the composed form (#19). Without normalization the two forms
// derive different Argon2 keys and decryption fails with ErrWrongPassword.
func TestWASMEncryptNormalizesPassword(t *testing.T) {
	original := []byte("cross-platform web volume")

	ciphertext, errCode := EncryptVolume(original, nfdPassword)
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}

	plaintext, errCode := DecryptVolume(ciphertext, nfcPassword)
	if errCode != 0 {
		t.Fatalf("decrypt with composed form failed (code %d): encrypt did not normalize to NFC", errCode)
	}
	if !bytes.Equal(plaintext, original) {
		t.Errorf("roundtrip mismatch\ngot:  %q\nwant: %q", plaintext, original)
	}
}
