package fileops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateSecureNoSymlinkRejectsSymlink locks the SEC-02 invariant: a
// pre-planted symlink at a write target is rejected before any file is opened,
// and the symlink's victim (size/mtime/content) is left untouched (no
// follow-through write or truncate).
func TestCreateSecureNoSymlinkRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()

	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideDir, 0755); err != nil {
		t.Fatalf("Create outside dir: %v", err)
	}
	victimPath := filepath.Join(outsideDir, "owned.pcv")
	if err := os.WriteFile(victimPath, []byte("outside"), 0600); err != nil {
		t.Fatalf("Create victim file: %v", err)
	}

	beforeInfo, err := os.Stat(victimPath)
	if err != nil {
		t.Fatalf("Stat victim file: %v", err)
	}
	beforeSize := beforeInfo.Size()
	beforeMod := beforeInfo.ModTime()

	outputPath := filepath.Join(tmpDir, "output.pcv")
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	f, err := CreateSecureNoSymlink(outputPath)
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("expected symlink rejection, got nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("error does not mention symlink: %v", err)
	}

	// Victim must be untouched: content, size, and mtime unchanged proves no
	// follow-through write or O_TRUNC truncate happened.
	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read victim file: %v", err)
	}
	if string(got) != "outside" {
		t.Fatalf("Victim file content modified: got %q, want %q", got, "outside")
	}

	afterInfo, err := os.Stat(victimPath)
	if err != nil {
		t.Fatalf("Stat victim file after: %v", err)
	}
	if afterInfo.Size() != beforeSize {
		t.Fatalf("Victim file size changed: got %d, want %d", afterInfo.Size(), beforeSize)
	}
	if !afterInfo.ModTime().Equal(beforeMod) {
		t.Fatalf("Victim file mtime changed: got %v, want %v", afterInfo.ModTime(), beforeMod)
	}
}

func TestOpenExistingNoSymlinkRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	victimPath := filepath.Join(tmpDir, "victim.pcv")
	if err := os.WriteFile(victimPath, []byte("victim"), 0600); err != nil {
		t.Fatalf("Create victim file: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv.incomplete")
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	f, err := OpenExistingNoSymlink(outputPath, os.O_WRONLY|os.O_APPEND)
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("expected symlink rejection, got nil error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("error does not mention symlink: %v", err)
	}

	got, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatalf("Read victim file: %v", err)
	}
	if string(got) != "victim" {
		t.Fatalf("Victim file content modified: got %q, want %q", got, "victim")
	}
}

// TestTempFilesOverwrittenBeforeUnlink locks the SEC-04 invariant: when a
// decrypt/abort cleanup path routes a sensitive temp artifact through
// OverwriteAndRemove, the artifact's bytes are best-effort overwritten with
// zeros BEFORE the file is unlinked, and the artifact no longer exists
// afterwards.
//
// Plaintext-vs-ciphertext distinction (Pitfall 3, RESEARCH Q1): of the SEC-04
// cleanup sites, the only genuinely-recoverable-PLAINTEXT artifact is the
// decrypt output `req.OutputFile + ".incomplete"` (decrypt.go) — a partially
// written decrypted file. The other temps (ctx.TempFile / ctx.RecombinedFile /
// the deniability .tmp) hold still-encrypted .pcv ciphertext; wiping them is
// cheap defense-in-depth, NOT the primary plaintext threat. This test asserts
// overwrite-before-unlink for BOTH classes so the invariant is pinned
// uniformly, but names the plaintext .incomplete explicitly as the genuine
// threat so reviewers aren't misled.
//
// Ordering proof: the test swaps the unexported removeFile seam (white-box,
// same package — no exported test seam ships in production binaries, WR-02) to
// capture the on-disk bytes at the instant after the overwrite but before the
// unlink. Asserting those captured bytes are all-zero proves the overwrite
// happened first.
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

			// Intercept the bytes at pre-unlink time via the unexported remove
			// seam (white-box, same package).
			var preUnlink []byte
			var sawRemove bool
			prev := removeFile
			removeFile = func(path string) error {
				sawRemove = true
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read artifact before unlink: %v", err)
				}
				preUnlink = b
				return os.Remove(path)
			}
			defer func() { removeFile = prev }()

			if err := OverwriteAndRemove(artifact); err != nil {
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

// TestOverwriteAndRemoveRemovesSymlinkWithoutOverwritingTarget locks the
// cleanup invariant for hostile .incomplete paths: cleanup may remove the leaf
// path, but it must never follow a symlink and overwrite the symlink target.
func TestOverwriteAndRemoveRemovesSymlinkWithoutOverwritingTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	link := filepath.Join(dir, "output.pcv.incomplete")

	original := []byte("do-not-zero")
	if err := os.WriteFile(victim, original, 0600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	if err := OverwriteAndRemove(link); err != nil {
		t.Fatalf("OverwriteAndRemove returned error: %v", err)
	}

	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("symlink still exists after cleanup: %v", err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("victim content changed: got %x, want %x", got, original)
	}
}

// TestOverwriteAndRemoveBestEffortMissing pins the best-effort contract: on a
// non-existent path the overwrite is skipped but the os.Remove error is still
// surfaced (the return value exists for testability; callers keep `_ =`).
func TestOverwriteAndRemoveBestEffortMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.incomplete")

	if err := OverwriteAndRemove(missing); err == nil {
		t.Fatal("expected a remove error for a non-existent path, got nil")
	}
}
