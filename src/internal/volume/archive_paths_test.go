package volume

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildZipEntryNamesUsesCommonSelectionRoot(t *testing.T) {
	tmpDir := t.TempDir()
	fileA := filepath.Join(tmpDir, "alpha", "one.txt")
	fileB := filepath.Join(tmpDir, "beta", "two.txt")

	if err := os.MkdirAll(filepath.Dir(fileA), 0755); err != nil {
		t.Fatalf("Create dir for fileA: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fileB), 0755); err != nil {
		t.Fatalf("Create dir for fileB: %v", err)
	}
	if err := os.WriteFile(fileA, []byte("one"), 0644); err != nil {
		t.Fatalf("Write fileA: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("two"), 0644); err != nil {
		t.Fatalf("Write fileB: %v", err)
	}

	commonRoot, names, err := buildZipEntryNames(&EncryptRequest{
		InputFiles: []string{fileA, fileB},
		OnlyFiles:  []string{fileA, fileB},
	})
	if err != nil {
		t.Fatalf("buildZipEntryNames: %v", err)
	}

	if commonRoot != tmpDir {
		t.Fatalf("Common root = %q, want %q", commonRoot, tmpDir)
	}
	if names[fileA] != "alpha/one.txt" {
		t.Fatalf("Entry for fileA = %q", names[fileA])
	}
	if names[fileB] != "beta/two.txt" {
		t.Fatalf("Entry for fileB = %q", names[fileB])
	}
}
