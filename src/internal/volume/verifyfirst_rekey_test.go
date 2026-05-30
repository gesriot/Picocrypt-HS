package volume

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
)

// TestVerifyFirstRekeyAbove60GiB proves (VER-01) that the verify-first MAC pass
// and the decrypt pass produce the SAME MAC across the rekey boundary, so a
// threshold-crossing volume verifies and decrypts byte-identically under
// VerifyFirst mode.
//
// Mechanism: lower crypto.RekeyThreshold via its test seam (D-01) BEFORE
// Encrypt/Decrypt — NewCounter copies the threshold at context-construction time
// (NewEncryptContext/NewDecryptContext), so the seam must be set first — then
// encrypt a synthetic plaintext comfortably LARGER than the lowered threshold so
// at least one rekey fires on BOTH the encrypt and decrypt passes.
//
// Non-vacuous guard: the plaintext size strictly exceeds the lowered
// crypto.RekeyThreshold, so the decrypt-pass Rekey() at decrypt.go:587 is forced
// on both passes (and the encrypt pass rekeys too). If the verify-first MAC ever
// diverged from the decrypt MAC across the boundary, verify-first would return
// perrors.ErrAuthFailed BEFORE emitting any output — so a green result with
// byte-identical output proves verify-MAC == decrypt-MAC. A deliberately broken
// Rekey() would make the encrypt/decrypt streams diverge and turn this test red.
func TestVerifyFirstRekeyAbove60GiB(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	// Lower the rekey threshold via the D-01 seam BEFORE Encrypt/Decrypt, restore via defer.
	const loweredThreshold = 4 * util.MiB
	prev := crypto.RekeyThreshold
	crypto.RekeyThreshold = loweredThreshold
	defer func() { crypto.RekeyThreshold = prev }()

	// Synthetic plaintext comfortably larger than the lowered threshold so >= 1
	// rekey fires on both the encrypt and decrypt passes (non-vacuous guard).
	const plaintextSize = 8 * util.MiB
	if plaintextSize <= int(crypto.RekeyThreshold) {
		t.Fatalf("vacuous test: plaintext (%d) must exceed lowered threshold (%d)", plaintextSize, crypto.RekeyThreshold)
	}
	plaintext := make([]byte, plaintextSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "rekey_input.bin")
	if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encryptedPath := filepath.Join(tmpDir, "rekey_input.bin.pcv")
	decryptedPath := filepath.Join(tmpDir, "rekey_decrypted.bin")

	const password = "rekey-boundary-test-password"

	encReq := &EncryptRequest{
		InputFile:  inputPath,
		OutputFile: encryptedPath,
		Password:   password,
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rsCodecs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt with VerifyFirst: the verify pass MACs the ciphertext, then the
	// decrypt pass re-derives keys and decrypts. Both cross the lowered rekey
	// boundary. A divergent verify MAC would fail-closed with ErrAuthFailed here.
	decReq := &DecryptRequest{
		InputFile:    encryptedPath,
		OutputFile:   decryptedPath,
		Password:     password,
		VerifyFirst:  true,
		ForceDecrypt: false,
		Reporter:     &GoldenTestReporter{},
		RSCodecs:     rsCodecs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt with VerifyFirst across rekey boundary failed: %v", err)
	}

	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("verify-first decrypt output not byte-identical across rekey boundary: got %d bytes, want %d bytes", len(decrypted), len(plaintext))
	}
}
