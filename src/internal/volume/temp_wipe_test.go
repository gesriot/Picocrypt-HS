package volume

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/fileops"
)

// TestTempFilesOverwrittenBeforeUnlink locks the SEC-04 invariant: when a
// decrypt/abort cleanup path routes a sensitive temp artifact through
// fileops.OverwriteAndRemove, the artifact's bytes are best-effort overwritten
// with zeros BEFORE the file is unlinked, and the artifact no longer exists
// afterwards.
//
// Plaintext-vs-ciphertext distinction (Pitfall 3, RESEARCH Q1): of the SEC-04
// cleanup sites, the only genuinely-recoverable-PLAINTEXT artifact is the
// decrypt output `req.OutputFile + ".incomplete"` (decrypt.go:753/777/868) — a
// partially-written decrypted file. The other temps (ctx.TempFile /
// ctx.RecombinedFile / the deniability .tmp) hold still-encrypted .pcv
// ciphertext; wiping them is cheap defense-in-depth, NOT the primary plaintext
// threat. This test asserts overwrite-before-unlink for BOTH classes so the
// invariant is pinned uniformly, but names the plaintext .incomplete explicitly
// as the genuine threat so reviewers aren't misled.
//
// Ordering proof: the test swaps fileops' remove seam to capture the on-disk
// bytes at the instant after the overwrite but before the unlink. Asserting
// those captured bytes are all-zero proves the overwrite happened first.
func TestTempFilesOverwrittenBeforeUnlink(t *testing.T) {
	cases := []struct {
		name      string
		suffix    string // mimics the real artifact name
		plaintext bool   // true = the genuine recoverable-plaintext threat
	}{
		{
			name:      "decrypt .incomplete (PLAINTEXT — the genuine T-04-04 threat)",
			suffix:    ".incomplete",
			plaintext: true,
		},
		{
			name:      "ciphertext temp (defense-in-depth)",
			suffix:    ".tmp",
			plaintext: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "output"+tc.suffix)

			// Non-zero content standing in for the recoverable fragment.
			content := bytes.Repeat([]byte{0xA5}, 300*1024) // > one 64 KiB chunk
			if err := os.WriteFile(artifact, content, 0600); err != nil {
				t.Fatalf("write artifact: %v", err)
			}

			// Intercept the bytes at pre-unlink time via the fileops remove seam.
			var preUnlink []byte
			var sawRemove bool
			restore := fileops.SwapRemoveForTest(func(path string) error {
				sawRemove = true
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read artifact before unlink: %v", err)
				}
				preUnlink = b
				return os.Remove(path)
			})
			defer restore()

			if err := fileops.OverwriteAndRemove(artifact); err != nil {
				t.Fatalf("OverwriteAndRemove returned error on happy path: %v", err)
			}

			if !sawRemove {
				t.Fatal("OverwriteAndRemove did not call the remove seam (never attempted unlink)")
			}

			// (a) The artifact must be gone.
			if _, err := os.Stat(artifact); !os.IsNotExist(err) {
				t.Fatalf("artifact still exists after OverwriteAndRemove: %v", err)
			}

			// (b) Its bytes must have been overwritten BEFORE unlink (ordering).
			if len(preUnlink) != len(content) {
				t.Fatalf("pre-unlink length changed (truncation? O_TRUNC?): got %d, want %d",
					len(preUnlink), len(content))
			}
			for i, b := range preUnlink {
				if b != 0 {
					t.Fatalf("byte %d was %#x, not zeroed before unlink (plaintext=%v)",
						i, b, tc.plaintext)
				}
			}
		})
	}
}

// TestOverwriteAndRemoveBestEffortMissing pins the best-effort contract: on a
// non-existent path the overwrite is skipped but the os.Remove error is still
// surfaced (the return value exists for testability; callers keep `_ =`).
func TestOverwriteAndRemoveBestEffortMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.incomplete")

	if err := fileops.OverwriteAndRemove(missing); err == nil {
		t.Fatal("expected a remove error for a non-existent path, got nil")
	}
}
