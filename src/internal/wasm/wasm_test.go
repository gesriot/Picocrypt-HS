package wasm

import (
	"bytes"
	"os"
	"testing"
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
