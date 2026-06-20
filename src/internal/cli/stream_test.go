package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsStdin(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"-", true},
		{"", false},
		{"stdin", false},
		{"/dev/stdin", false},
		{"file.txt", false},
		{"-file", false},
		{"file-", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsStdin(tt.path); got != tt.want {
				t.Errorf("IsStdin(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsStdout(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"-", true},
		{"", false},
		{"stdout", false},
		{"/dev/stdout", false},
		{"file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsStdout(tt.path); got != tt.want {
				t.Errorf("IsStdout(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestBufferStdinToTemp(t *testing.T) {
	testData := []byte("test data for stdin buffering\nwith multiple lines\n")

	// Create pipe to simulate stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Save and replace stdin
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Write test data in goroutine
	go func() {
		w.Write(testData)
		w.Close()
	}()

	// Call function under test
	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	defer os.Remove(tmpPath)

	// Verify file exists with correct permissions
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	// Windows doesn't support Unix-style permissions
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify content
	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Errorf("content mismatch\ngot:  %q\nwant: %q", content, testData)
	}
}

func TestBufferStdinToTempEmpty(t *testing.T) {
	// Test with empty stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Close immediately (empty input)
	w.Close()

	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	defer os.Remove(tmpPath)

	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
	// The 0600 chmod must apply even on the empty-stdin path (mirrors the
	// non-empty sibling). Mutation: dropping the Chmod(0600) in BufferStdinToTemp
	// would leak stdin plaintext staging under a world-readable mode.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestBufferStdinToTempLarge(t *testing.T) {
	// Test with larger data (1 MiB)
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	go func() {
		w.Write(testData)
		w.Close()
	}()

	tmpPath, err := BufferStdinToTemp("")
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	defer os.Remove(tmpPath)

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("reading temp file: %v", err)
	}
	if !bytes.Equal(content, testData) {
		t.Error("large data content mismatch")
	}
}

func TestBufferStdinToTempDoesNotUseOutputDir(t *testing.T) {
	testData := []byte("stdin output-path isolation")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	go func() {
		_, _ = w.Write(testData)
		_ = w.Close()
	}()

	outputDir := t.TempDir()
	outputPath := filepath.Join(outputDir, "output.pcv")

	tmpPath, err := BufferStdinToTemp(outputPath)
	if err != nil {
		t.Fatalf("BufferStdinToTemp() error = %v", err)
	}
	defer os.Remove(tmpPath)

	if filepath.Dir(tmpPath) == outputDir {
		t.Fatalf("stdin temp file should not be created in output dir %s", outputDir)
	}
}

func TestCreateTempOutput(t *testing.T) {
	tmpPath, err := CreateTempOutput(0)
	if err != nil {
		t.Fatalf("CreateTempOutput() error = %v", err)
	}
	defer os.Remove(tmpPath)

	// Verify file exists with correct permissions
	info, err := os.Stat(tmpPath)
	if err != nil {
		t.Fatalf("temp file not found: %v", err)
	}
	// Windows doesn't support Unix-style permissions
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}

	// File should be empty initially
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}
}

func TestStreamFileToStdout(t *testing.T) {
	testData := []byte("output data to stream\nwith multiple lines\n")

	// Create temp file with test data
	tmpFile, err := os.CreateTemp("", "stream-test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(testData); err != nil {
		tmpFile.Close()
		t.Fatal(err)
	}
	tmpFile.Close()

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	os.Stdout = w

	// Stream in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- StreamFileToStdout(tmpPath)
		w.Close()
	}()

	// Read captured output
	var captured bytes.Buffer
	io.Copy(&captured, r)
	os.Stdout = oldStdout

	if err := <-errCh; err != nil {
		t.Fatalf("StreamFileToStdout() error = %v", err)
	}

	if !bytes.Equal(captured.Bytes(), testData) {
		t.Errorf("output mismatch\ngot:  %q\nwant: %q", captured.Bytes(), testData)
	}
}

func TestStreamFileToStdoutNonexistent(t *testing.T) {
	err := StreamFileToStdout("/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestCleanupTempFilesRemovesTemp verifies that the stdin/stdout staging temps
// are removed by cleanupTempFiles. Cleanup is plain os.Remove (no shredding —
// overwrite-before-unlink was dropped as useless on flash/CoW filesystems);
// the invariant is only that the temp no longer exists afterwards.
func TestCleanupTempFilesRemovesTemp(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
	}{
		{"decrypt-to-stdout plaintext temp", "picocrypt-out-"},
		{"encrypt-from-stdin plaintext temp", "picocrypt-stdin-"},
		{"ciphertext staging temp", "picocrypt-cipher-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tmp := filepath.Join(dir, tc.prefix+"fixture")
			if err := os.WriteFile(tmp, []byte("plaintext fragment"), 0o600); err != nil {
				t.Fatalf("write temp: %v", err)
			}

			cleanupTempFiles(tmp)

			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Fatalf("temp still exists after cleanup: %v", err)
			}
		})
	}
}

// TestCleanupTempFilesRemovesAllProvidedTemps proves the shared helper handles
// the real call shape from both runEncrypt and runDecrypt: a stdin staging temp
// AND a stdout staging temp are both removed in one cleanup pass.
func TestCleanupTempFilesRemovesAllProvidedTemps(t *testing.T) {
	dir := t.TempDir()
	stdinTemp := filepath.Join(dir, "picocrypt-stdin-a")
	stdoutTemp := filepath.Join(dir, "picocrypt-out-b")
	for _, p := range []string{stdinTemp, stdoutTemp} {
		if err := os.WriteFile(p, []byte("plaintext fragment"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	cleanupTempFiles(stdinTemp, stdoutTemp)

	for _, p := range []string{stdinTemp, stdoutTemp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp %s still exists after cleanup", p)
		}
	}
}

// TestCleanupTempFilesSkipsEmptyPaths guards the "no temp was created" case:
// runEncrypt/runDecrypt pass "" when stdin/stdout buffering never ran, and the
// helper must skip empty paths rather than attempting to remove a sibling file.
func TestCleanupTempFilesSkipsEmptyPaths(t *testing.T) {
	dir := t.TempDir()
	bystander := filepath.Join(dir, "bystander")
	if err := os.WriteFile(bystander, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write bystander: %v", err)
	}

	cleanupTempFiles("", "")

	if _, err := os.Stat(bystander); err != nil {
		t.Fatalf("cleanupTempFiles disturbed an unrelated file on empty input: %v", err)
	}
}

func TestStreamFileToStdoutLarge(t *testing.T) {
	// Test streaming 1 MiB
	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	tmpFile, err := os.CreateTemp("", "stream-large-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(testData); err != nil {
		tmpFile.Close()
		t.Fatal(err)
	}
	tmpFile.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout
	os.Stdout = w

	errCh := make(chan error, 1)
	go func() {
		errCh <- StreamFileToStdout(tmpPath)
		w.Close()
	}()

	var captured bytes.Buffer
	io.Copy(&captured, r)
	os.Stdout = oldStdout

	if err := <-errCh; err != nil {
		t.Fatalf("StreamFileToStdout() error = %v", err)
	}

	if !bytes.Equal(captured.Bytes(), testData) {
		t.Error("large data output mismatch")
	}
}
