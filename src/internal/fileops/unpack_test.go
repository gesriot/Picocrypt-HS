package fileops

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"Picocrypt-NG/internal/util"
)

// TestUnpackPathTraversalPrevention verifies that zip files with "../" in
// filenames are rejected to prevent path traversal attacks.
func TestUnpackPathTraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a malicious zip file with path traversal attempt
	maliciousZipPath := filepath.Join(tmpDir, "malicious.zip")
	createMaliciousZip(t, maliciousZipPath)

	// Attempt to unpack - should fail
	err := Unpack(UnpackOptions{
		ZipPath:    maliciousZipPath,
		ExtractDir: filepath.Join(tmpDir, "extracted"),
	})

	if err == nil {
		t.Fatal("Expected error for path traversal attempt, got nil")
	}

	expectedErr := "potentially malicious zip item path"
	if err.Error() != expectedErr {
		t.Errorf("Expected error %q, got %q", expectedErr, err.Error())
	}

	t.Logf("Path traversal correctly blocked: %v", err)
}

// TestUnpackPathTraversalVariants tests various path traversal attempts
func TestUnpackPathTraversalVariants(t *testing.T) {
	maliciousPaths := []string{
		"../etc/passwd",
		"foo/../../../etc/passwd",
		"..\\windows\\system32\\config\\sam",
		"normal/../../etc/passwd",
		"a/b/c/../../../../../../../etc/passwd",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			tmpDir := t.TempDir()
			zipPath := filepath.Join(tmpDir, "test.zip")

			// Create zip with malicious path
			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatalf("Create zip file: %v", err)
			}

			w := zip.NewWriter(f)
			_, err = w.Create(malPath)
			if err != nil {
				// Some paths may be rejected by the zip library itself
				_ = w.Close()
				_ = f.Close()
				t.Skipf("Zip library rejected path: %v", err)
				return
			}
			_ = w.Close()
			_ = f.Close()

			// Attempt to unpack
			err = Unpack(UnpackOptions{
				ZipPath:    zipPath,
				ExtractDir: filepath.Join(tmpDir, "out"),
			})

			if err == nil {
				t.Errorf("Expected error for malicious path %q, got nil", malPath)
			} else {
				t.Logf("Path %q correctly blocked: %v", malPath, err)
			}
		})
	}
}

func TestUnpackRejectsWindowsTrimTraversalVariants(t *testing.T) {
	maliciousPaths := []string{
		".. /evil.txt",
		".. ./evil.txt",
		"safe/.. /evil.txt",
		`safe\.. \evil.txt`,
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			tmpDir := t.TempDir()
			zipPath := filepath.Join(tmpDir, "test.zip")

			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatalf("Create zip file: %v", err)
			}

			w := zip.NewWriter(f)
			fw, err := w.Create(malPath)
			if err != nil {
				t.Fatalf("Create entry %q: %v", malPath, err)
			}
			if _, err := fw.Write([]byte("test")); err != nil {
				t.Fatalf("Write entry: %v", err)
			}
			_ = w.Close()
			_ = f.Close()

			err = Unpack(UnpackOptions{
				ZipPath:    zipPath,
				ExtractDir: filepath.Join(tmpDir, "out"),
			})

			if err == nil || err.Error() != "potentially malicious zip item path" {
				t.Fatalf("malicious path %q produced err %v", malPath, err)
			}
		})
	}
}

func TestHasUnsafeWindowsTrimTraversalComponent(t *testing.T) {
	testCases := []struct {
		name string
		path string
		want bool
	}{
		{name: "Normal file", path: "safe/file.txt", want: false},
		{name: "Double dots in filename allowed", path: "safe/file..txt", want: false},
		{name: "Parent with trailing space", path: ".. /evil.txt", want: true},
		{name: "Parent with trailing dot", path: "../evil.txt", want: true},
		{name: "Parent with trailing dot and space", path: ".. ./evil.txt", want: true},
		{name: "Nested parent with trailing space", path: "safe/.. /evil.txt", want: true},
		{name: "Backslash separator variant", path: `safe\.. \evil.txt`, want: true},
		{name: "Single dot with trailing space", path: ". /evil.txt", want: true},
		{name: "Triple dot segment", path: ".../evil.txt", want: true},
		{name: "Triple dot with trailing space", path: "... /evil.txt", want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasUnsafeWindowsTrimTraversalComponent(tc.path)
			if got != tc.want {
				t.Fatalf("hasUnsafeWindowsTrimTraversalComponent(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestUnpackRejectsWindowsTrimDotLikeVariants(t *testing.T) {
	maliciousPaths := []string{
		". /evil.txt",
		".../evil.txt",
		"... /evil.txt",
	}

	for _, malPath := range maliciousPaths {
		t.Run(malPath, func(t *testing.T) {
			tmpDir := t.TempDir()
			zipPath := filepath.Join(tmpDir, "dotlike.zip")

			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatalf("Create zip file: %v", err)
			}

			w := zip.NewWriter(f)
			fw, err := w.Create(malPath)
			if err != nil {
				t.Fatalf("Create entry %q: %v", malPath, err)
			}
			if _, err := fw.Write([]byte("test")); err != nil {
				t.Fatalf("Write entry: %v", err)
			}
			_ = w.Close()
			_ = f.Close()

			err = Unpack(UnpackOptions{
				ZipPath:    zipPath,
				ExtractDir: filepath.Join(tmpDir, "out"),
			})

			if err == nil || !strings.Contains(err.Error(), "potentially malicious zip item path") {
				t.Fatalf("malicious path %q produced err %v", malPath, err)
			}
		})
	}
}

func TestUnpackAllowsHighlyCompressedFileBelowFloor(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "small.zip")
	data := bytes.Repeat([]byte("A"), util.MiB/2)
	createDeflatedZipWithContent(t, zipPath, "small.txt", data)

	extractDir := filepath.Join(tmpDir, "out")
	if err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	}); err != nil {
		t.Fatalf("Unpack failed below floor: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(extractDir, "small.txt"))
	if err != nil {
		t.Fatalf("Read unpacked file: %v", err)
	}
	if !bytes.Equal(content, data) {
		t.Fatal("unpacked content mismatch")
	}
}

func TestUnpackRejectsHighlyCompressedFileAboveFloor(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "bomb.zip")
	data := bytes.Repeat([]byte("A"), 2*util.MiB)
	createDeflatedZipWithContent(t, zipPath, "bomb.txt", data)

	err := Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: filepath.Join(tmpDir, "out"),
	})
	if err == nil {
		t.Fatal("expected decompression limit error")
	}
	if !strings.Contains(err.Error(), "decompression limit exceeded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestUnpackNormalPaths verifies that normal paths work correctly
func TestUnpackNormalPaths(t *testing.T) {
	normalPaths := []string{
		"file.txt",
		"dir/file.txt",
		"dir/subdir/file.txt",
		"a.b.c/d.e.f/file.txt",
		// Files with double dots in name (NOT path traversal)
		"test..txt",
		"file..backup",
		"dir/file..copy.txt",
		"Исследования..копия.docx",
	}

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "normal.zip")

	// Create zip with normal paths
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	for _, path := range normalPaths {
		fw, err := w.Create(path)
		if err != nil {
			t.Fatalf("Create entry %q: %v", path, err)
		}
		_, _ = fw.Write([]byte("test content"))
	}
	_ = w.Close()
	_ = f.Close()

	// Unpack should succeed
	extractDir := filepath.Join(tmpDir, "extracted")
	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})

	if err != nil {
		t.Fatalf("Unpack failed for normal paths: %v", err)
	}

	// Verify files were created
	for _, path := range normalPaths {
		fullPath := filepath.Join(extractDir, path)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Errorf("Expected file %q to exist", fullPath)
		}
	}

	t.Log("Normal paths unpacked successfully")
}

func createDeflatedZipWithContent(t *testing.T, zipPath, name string, data []byte) {
	t.Helper()

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	fw, err := w.Create(name)
	if err != nil {
		t.Fatalf("Create entry %q: %v", name, err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("Write entry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close zip writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close zip file: %v", err)
	}
}

func TestUnpackAllowsSystemTempDirSymlinkPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	resolvedTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Skipf("Cannot resolve temp dir symlinks on this platform: %v", err)
	}
	if resolvedTmpDir == tmpDir {
		t.Skip("temp dir path has no symlinked prefix on this platform")
	}

	zipPath := filepath.Join(tmpDir, "normal.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	fw, err := w.Create("file.txt")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	if _, err := fw.Write([]byte("test content")); err != nil {
		t.Fatalf("Write entry: %v", err)
	}
	_ = w.Close()
	_ = f.Close()

	extractDir := filepath.Join(tmpDir, "extracted")
	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})
	if err != nil {
		t.Fatalf("Expected symlinked temp dir prefix to be allowed, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(extractDir, "file.txt")); err != nil {
		t.Fatalf("Expected extracted file to exist: %v", err)
	}
}

// TestUnpackCancellation verifies that unpack can be cancelled
func TestUnpackCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")

	// Create zip with multiple files
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	for i := 0; i < 10; i++ {
		fw, err := w.CreateHeader(&zip.FileHeader{
			Name:   filepath.Join("dir", "file"+string(rune('0'+i))+".txt"),
			Method: zip.Store,
		})
		if err != nil {
			t.Fatalf("Create entry: %v", err)
		}
		_, _ = fw.Write([]byte("test content for file"))
	}
	_ = w.Close()
	_ = f.Close()

	// Cancel after first file
	cancelAfter := 1
	cancelled := false
	count := 0

	extractDir := filepath.Join(tmpDir, "extracted")
	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
		Cancel: func() bool {
			count++
			if count > cancelAfter && !cancelled {
				cancelled = true
				return true
			}
			return false
		},
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}

	t.Logf("Unpack correctly cancelled: %v", err)
}

func TestUnpackRejectsPreexistingSymlinkDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideDir, 0700); err != nil {
		t.Fatalf("Create outside dir: %v", err)
	}

	extractDir := filepath.Join(tmpDir, "extract")
	if err := os.MkdirAll(extractDir, 0700); err != nil {
		t.Fatalf("Create extract dir: %v", err)
	}

	linkPath := filepath.Join(extractDir, "escape")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	zipPath := filepath.Join(tmpDir, "payload.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	fw, err := w.Create("escape/payload.txt")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	if _, err := fw.Write([]byte("payload")); err != nil {
		t.Fatalf("Write entry: %v", err)
	}
	_ = w.Close()
	_ = f.Close()

	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})

	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("Expected symlink rejection, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(outsideDir, "payload.txt")); !os.IsNotExist(err) {
		t.Fatalf("Payload escaped extraction root")
	}
}

func TestUnpackRejectsSymlinkLeaf(t *testing.T) {
	tmpDir := t.TempDir()
	outsideFile := filepath.Join(tmpDir, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0600); err != nil {
		t.Fatalf("Create outside file: %v", err)
	}

	extractDir := filepath.Join(tmpDir, "extract")
	if err := os.MkdirAll(extractDir, 0700); err != nil {
		t.Fatalf("Create extract dir: %v", err)
	}

	leafPath := filepath.Join(extractDir, "leaf.txt")
	if err := os.Symlink(outsideFile, leafPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	zipPath := filepath.Join(tmpDir, "leaf.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	fw, err := w.Create("leaf.txt")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	if _, err := fw.Write([]byte("replacement")); err != nil {
		t.Fatalf("Write entry: %v", err)
	}
	_ = w.Close()
	_ = f.Close()

	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})

	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("Expected symlink rejection, got %v", err)
	}

	got, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatalf("Read outside file: %v", err)
	}
	if string(got) != "outside" {
		t.Fatalf("Outside file was modified: %q", got)
	}
}

func TestUnpackRejectsSymlinkedExtractionRootAncestor(t *testing.T) {
	tmpDir := t.TempDir()
	outsideRoot := filepath.Join(tmpDir, "outside-root")
	if err := os.MkdirAll(outsideRoot, 0700); err != nil {
		t.Fatalf("Create outside root: %v", err)
	}

	linkPath := filepath.Join(tmpDir, "link")
	if err := os.Symlink(outsideRoot, linkPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	extractDir := filepath.Join(linkPath, "extract")
	zipPath := filepath.Join(tmpDir, "root-ancestor.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}

	w := zip.NewWriter(f)
	fw, err := w.Create("payload.txt")
	if err != nil {
		t.Fatalf("Create entry: %v", err)
	}
	if _, err := fw.Write([]byte("payload")); err != nil {
		t.Fatalf("Write entry: %v", err)
	}
	_ = w.Close()
	_ = f.Close()

	err = Unpack(UnpackOptions{
		ZipPath:    zipPath,
		ExtractDir: extractDir,
	})

	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("Expected symlink rejection, got %v", err)
	}

	if _, err := os.Stat(filepath.Join(outsideRoot, "extract", "payload.txt")); !os.IsNotExist(err) {
		t.Fatalf("Payload escaped extraction root through symlinked ancestor")
	}
}

func TestWalkExtractionRootAllowsTrustedLeadingSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realRoot := filepath.Join(tmpDir, "real-root")
	if err := os.MkdirAll(realRoot, 0700); err != nil {
		t.Fatalf("Create real root: %v", err)
	}

	aliasRoot := filepath.Join(tmpDir, "alias-root")
	if err := os.Symlink(realRoot, aliasRoot); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	got, err := walkExtractionRoot(tmpDir, []string{"alias-root", "extract"}, true, true)
	if err != nil {
		t.Fatalf("Expected trusted leading symlink to be allowed, got %v", err)
	}

	want := filepath.Join(realRoot, "extract")
	resolvedWant, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("Resolve expected extraction root: %v", err)
	}
	if got != resolvedWant {
		t.Fatalf("Expected resolved extraction root %q, got %q", resolvedWant, got)
	}

	info, err := os.Stat(want)
	if err != nil {
		t.Fatalf("Stat resolved extraction root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Resolved extraction root is not a directory: %s", want)
	}
}

func TestWalkExtractionRootRejectsNestedSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	parent := filepath.Join(tmpDir, "parent")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatalf("Create parent dir: %v", err)
	}

	outsideRoot := filepath.Join(tmpDir, "outside-root")
	if err := os.MkdirAll(outsideRoot, 0700); err != nil {
		t.Fatalf("Create outside root: %v", err)
	}

	linkPath := filepath.Join(parent, "escape")
	if err := os.Symlink(outsideRoot, linkPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	got, err := walkExtractionRoot(tmpDir, []string{"parent", "escape", "extract"}, true, true)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("Expected nested symlink rejection, got path %q err %v", got, err)
	}

	if _, statErr := os.Stat(filepath.Join(outsideRoot, "extract")); !os.IsNotExist(statErr) {
		t.Fatalf("Nested symlink unexpectedly allowed extraction outside trusted root")
	}
}

func TestAllowLeadingExtractionRootSymlink(t *testing.T) {
	tmpDir := t.TempDir()

	if !allowLeadingExtractionRootSymlink(filepath.Join(tmpDir, "child"), tmpDir) {
		t.Fatal("Expected extraction root under temp dir to allow trusted leading symlink handling")
	}

	if allowLeadingExtractionRootSymlink(filepath.Join(tmpDir, "..", "outside"), tmpDir) {
		t.Fatal("Did not expect extraction root outside temp dir to allow trusted leading symlink handling")
	}
}

// createMaliciousZip creates a zip file with a path traversal attempt
func createMaliciousZip(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create zip file: %v", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	// Create a file with path traversal in name
	fw, err := w.Create("../escape.txt")
	if err != nil {
		t.Fatalf("Create malicious entry: %v", err)
	}
	_, _ = fw.Write([]byte("malicious content"))
}
