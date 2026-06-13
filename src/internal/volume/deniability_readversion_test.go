package volume

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

// TestIsDeniableReturnsFalseOnVersionReadError covers IsDeniable's I/O-error
// branch (WR-03): a file large enough to clear the size pre-guard
// (>= salt(16) + nonce(24) + header.BaseHeaderSize) but whose version-prefix
// read fails must classify as non-deniable ("cannot confirm"), never deniable.
//
// The branch is unreachable on a real filesystem — a file that Stat reports as
// >= the minimum can always have its first 15 bytes read — so a package-level
// read seam (isDeniableReadVersion, mirroring newDeniabilityReader) injects the
// failure deterministically.
func TestIsDeniableReturnsFalseOnVersionReadError(t *testing.T) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("Failed to create RS codecs: %v", err)
	}

	// A real file that clears the size pre-guard, so IsDeniable proceeds to the
	// version read rather than rejecting early on size.
	minDeniable := 16 + 24 + header.BaseHeaderSize
	path := filepath.Join(t.TempDir(), "readfail.pcv")
	if err := os.WriteFile(path, make([]byte, minDeniable), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Inject a read failure at the version-prefix read; restore afterwards.
	prev := isDeniableReadVersion
	isDeniableReadVersion = func(io.Reader, []byte) (int, error) {
		return 0, io.ErrUnexpectedEOF
	}
	t.Cleanup(func() { isDeniableReadVersion = prev })

	if IsDeniable(path, rsCodecs) {
		t.Error("version read error must classify as non-deniable, not deniable")
	}
}
