package wasm

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
)

func TestDecryptV1(t *testing.T) {
	// Read the v1 test volume (password-only, no keyfiles)
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v1.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	// Decrypt with password "test"
	plaintext, errCode := DecryptVolume(volumeData, "test")
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	// Read expected content
	expected, err := os.ReadFile("../../testdata/golden/pico_test.txt")
	if err != nil {
		t.Fatalf("failed to read expected file: %v", err)
	}

	// Normalize line endings: git may convert \n → \r\n on Windows checkout
	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(plaintext, expected) {
		t.Errorf("decrypted content doesn't match expected\ngot: %q\nwant: %q", plaintext, expected)
	}
}

func TestDecryptV2(t *testing.T) {
	// Read the v2 test volume (password-only, no keyfiles)
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v2.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	// Decrypt with password "test"
	plaintext, errCode := DecryptVolume(volumeData, "test")
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	// Read expected content
	expected, err := os.ReadFile("../../testdata/golden/pico_test.txt")
	if err != nil {
		t.Fatalf("failed to read expected file: %v", err)
	}

	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(plaintext, expected) {
		t.Errorf("decrypted content doesn't match expected\ngot: %q\nwant: %q", plaintext, expected)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v2.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	_, errCode := DecryptVolume(volumeData, "wrongpassword")
	if errCode != ErrWrongPassword {
		t.Errorf("expected error code %d, got %d", ErrWrongPassword, errCode)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	original := []byte("Hello, Picocrypt-NG WASM world!")
	password := "testpassword123"

	// Encrypt
	ciphertext, errCode := EncryptVolume(original, password)
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}

	// Decrypt
	plaintext, errCode := DecryptVolume(ciphertext, password)
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	if !bytes.Equal(plaintext, original) {
		t.Errorf("roundtrip failed\ngot: %q\nwant: %q", plaintext, original)
	}
}

func TestEncryptDecryptLargerFile(t *testing.T) {
	// Create a larger test file (100KB)
	original := make([]byte, 100*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}
	password := "testpassword123"

	// Encrypt
	ciphertext, errCode := EncryptVolume(original, password)
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}

	// Decrypt
	plaintext, errCode := DecryptVolume(ciphertext, password)
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	if !bytes.Equal(plaintext, original) {
		t.Errorf("roundtrip failed for larger file")
	}
}

func TestWASMUsesWriteAuthValues(t *testing.T) {
	originalWriteAuthValues := writeAuthValues
	defer func() {
		writeAuthValues = originalWriteAuthValues
	}()

	sentinelKeyHash := bytes.Repeat([]byte{0xA1}, header.KeyHashSize)
	sentinelKeyfileHash := bytes.Repeat([]byte{0xB2}, header.KeyfileHashSize)
	sentinelAuthTag := bytes.Repeat([]byte{0xC3}, header.AuthTagSize)
	var calls int

	writeAuthValues = func(w io.WriterAt, offset int64, keyHash, keyfileHash, authTag []byte, rs *encoding.RSCodecs) error {
		calls++
		if offset != header.AuthValuesOffset(0) {
			t.Errorf("auth values offset = %d; want %d", offset, header.AuthValuesOffset(0))
		}
		if len(keyHash) != header.KeyHashSize {
			t.Errorf("keyHash size = %d; want %d", len(keyHash), header.KeyHashSize)
		}
		if len(keyfileHash) != header.KeyfileHashSize {
			t.Errorf("keyfileHash size = %d; want %d", len(keyfileHash), header.KeyfileHashSize)
		}
		if len(authTag) != header.AuthTagSize {
			t.Errorf("authTag size = %d; want %d", len(authTag), header.AuthTagSize)
		}

		return originalWriteAuthValues(w, offset, sentinelKeyHash, sentinelKeyfileHash, sentinelAuthTag, rs)
	}

	volumeData, errCode := EncryptVolume([]byte("phase 6 wasm auth writer guard"), "phase6-password")
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}
	if calls != 1 {
		t.Fatalf("writeAuthValues calls = %d; want 1", calls)
	}

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}
	result, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if !bytes.Equal(result.Header.KeyHash, sentinelKeyHash) {
		t.Fatal("WASM header key hash was not written by writeAuthValues")
	}
	if !bytes.Equal(result.Header.KeyfileHash, sentinelKeyfileHash) {
		t.Fatal("WASM header keyfile hash was not written by writeAuthValues")
	}
	if !bytes.Equal(result.Header.AuthTag, sentinelAuthTag) {
		t.Fatal("WASM header auth tag was not written by writeAuthValues")
	}
}

func TestWASMRoundtripDesktopDecrypt(t *testing.T) {
	original := []byte("Phase 6 WASM standard volume decrypts through the shared desktop volume path.")
	password := "phase6-desktop-interop"

	volumeData, errCode := EncryptVolume(original, password)
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}

	tmpDir := t.TempDir()
	encryptedPath := filepath.Join(tmpDir, "wasm-output.pcv")
	decryptedPath := filepath.Join(tmpDir, "desktop-output.txt")
	if err := os.WriteFile(encryptedPath, volumeData, 0600); err != nil {
		t.Fatalf("write encrypted volume: %v", err)
	}

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   password,
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("volume.Decrypt failed: %v", err)
	}

	plaintext, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(plaintext, original) {
		t.Fatalf("desktop decrypt output mismatch\ngot:  %q\nwant: %q", plaintext, original)
	}
}
