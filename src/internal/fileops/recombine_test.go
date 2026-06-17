package fileops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestRecombineSourceCloseFailureRemovesOutput asserts that when a source-chunk
// close fails mid-recombine, the partial output file is removed before Recombine
// returns.  Before the fix the fin.Close error path returns without calling
// os.Remove(outputPath), leaving a partial output on disk.
//
// Failure injection: recombineCloseFn is overridden to return an error for chunk 0.
func TestRecombineSourceCloseFailureRemovesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	chunk0 := basePath + ".0"
	chunk1 := basePath + ".1"
	if err := os.WriteFile(chunk0, bytes.Repeat([]byte{0xAA}, 512), 0644); err != nil {
		t.Fatalf("create chunk 0: %v", err)
	}
	if err := os.WriteFile(chunk1, bytes.Repeat([]byte{0xBB}, 512), 0644); err != nil {
		t.Fatalf("create chunk 1: %v", err)
	}

	// Override the close hook so that closing chunk 0 returns a synthetic error.
	// Restore afterward so other tests are unaffected.
	orig := recombineCloseFn
	recombineCloseFn = func(f *os.File) error {
		if filepath.Base(f.Name()) == "test.pcv.0" {
			_ = f.Close() // actually close the fd so we don't leak it
			return fmt.Errorf("injected close failure on %s", f.Name())
		}
		return f.Close()
	}
	t.Cleanup(func() { recombineCloseFn = orig })

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected error from injected close failure, got nil")
	}

	// The partial output file must NOT remain after the error.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("partial output %q should be removed after source-close failure; stat: %v", outputPath, statErr)
	}
}

// TestRecombineSyncFailureRemovesOutput asserts that when fout.Sync() fails,
// the partial output file is removed before Recombine returns.  Before the fix
// the Sync error path returns without calling os.Remove(outputPath).
func TestRecombineSyncFailureRemovesOutput(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	if err := os.WriteFile(basePath+".0", bytes.Repeat([]byte{0xCC}, 256), 0644); err != nil {
		t.Fatalf("create chunk: %v", err)
	}

	orig := recombineSyncFn
	recombineSyncFn = func(f *os.File) error {
		return fmt.Errorf("injected sync failure")
	}
	t.Cleanup(func() { recombineSyncFn = orig })

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected error from injected sync failure, got nil")
	}

	// The partial output file must NOT remain.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("partial output %q should be removed after sync failure; stat: %v", outputPath, statErr)
	}
}
