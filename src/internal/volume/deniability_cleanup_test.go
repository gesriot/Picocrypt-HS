package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

func TestRemoveDeniabilityWipesTempOnVerificationFailure(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	tmpDir := t.TempDir()
	wrappedPath := filepath.Join(tmpDir, "wrapped-invalid-inner.pcv")
	innerPlaintext := bytes.Repeat([]byte("invalid inner volume plaintext; "), 4)
	if err := os.WriteFile(wrappedPath, innerPlaintext, 0600); err != nil {
		t.Fatalf("write invalid inner volume: %v", err)
	}

	const password = "deniability-cleanup-password"
	if err := AddDeniability(wrappedPath, password, nil); err != nil {
		t.Fatalf("AddDeniability failed: %v", err)
	}

	tmpPath := wrappedPath + ".tmp"
	prevWipe := wipeDeniabilityTemp
	var sawTemp bool
	var sawPlaintext bool
	wipeDeniabilityTemp = func(path string) error {
		if path == tmpPath {
			sawTemp = true
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("read temp before wipe: %v", readErr)
			}
			sawPlaintext = bytes.Contains(data, innerPlaintext)
		}
		return prevWipe(path)
	}
	defer func() {
		wipeDeniabilityTemp = prevWipe
	}()

	decryptedPath, err := RemoveDeniability(wrappedPath, password, nil, rs)
	if err == nil {
		t.Fatalf("RemoveDeniability succeeded for invalid inner volume, returned %q", decryptedPath)
	}
	if !sawTemp {
		t.Fatalf("RemoveDeniability did not wipe temp path %s on verification failure", tmpPath)
	}
	if !sawPlaintext {
		t.Fatalf("wipe hook did not observe decrypted inner plaintext before removal")
	}
	if _, err := os.Lstat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp path still exists after cleanup: %v", err)
	}
}
