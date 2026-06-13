package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// TestRemoveDeniabilityRemovesTempOnVerificationFailure locks the cleanup
// invariant: when RemoveDeniability decrypts a deniability wrapper whose inner
// payload is not a valid volume, it must remove the decrypted .tmp staging file
// rather than leaving the recovered inner plaintext on disk. Cleanup is plain
// os.Remove (no shredding — overwrite-before-unlink was dropped as useless on
// flash/CoW filesystems); the only invariant is that the temp is gone.
func TestRemoveDeniabilityRemovesTempOnVerificationFailure(t *testing.T) {
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

	decryptedPath, err := RemoveDeniability(wrappedPath, password, nil, rs)
	if err == nil {
		t.Fatalf("RemoveDeniability succeeded for invalid inner volume, returned %q", decryptedPath)
	}
	if _, err := os.Lstat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp path still exists after cleanup: %v", err)
	}
}
