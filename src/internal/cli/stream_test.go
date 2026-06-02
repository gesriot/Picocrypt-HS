package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"Picocrypt-NG/internal/fileops"
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
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
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
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("temp file permissions = %o, want 0600", info.Mode().Perm())
	}

	// File should be empty initially
	if info.Size() != 0 {
		t.Errorf("expected empty file, got size %d", info.Size())
	}

	// Verify we can write to it (volume package will reopen)
	if err := os.WriteFile(tmpPath, []byte("test"), 0600); err != nil {
		t.Errorf("cannot write to temp file: %v", err)
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

// TestWipeTempFileDefaultsToSecurePrimitive ensures the production default of the
// wipeTempFile seam is the zero-overwrite primitive, not a bare os.Remove. The
// routing tests below swap the seam, so without this check a regression that
// rebound the default to a non-zeroing remove would still leave them green while
// silently dropping the overwrite-before-unlink guarantee.
func TestWipeTempFileDefaultsToSecurePrimitive(t *testing.T) {
	got := reflect.ValueOf(wipeTempFile).Pointer()
	want := reflect.ValueOf(fileops.OverwriteAndRemove).Pointer()
	if got != want {
		t.Fatal("wipeTempFile default is not fileops.OverwriteAndRemove; temp files may not be zero-overwritten before unlink")
	}
}

// TestCleanupTempFilesRoutesThroughSecureWipe verifies that the stdin/stdout
// staging temps are removed through the secure wipe path rather than a bare
// os.Remove. Overwrite-before-unlink ordering itself is covered by
// fileops.TestTempFilesOverwrittenBeforeUnlink; here we only check the routing.
func TestCleanupTempFilesRoutesThroughSecureWipe(t *testing.T) {
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
			content := bytes.Repeat([]byte{0xA5}, 300*1024) // > one 64 KiB overwrite chunk
			if err := os.WriteFile(tmp, content, 0600); err != nil {
				t.Fatalf("write temp: %v", err)
			}

			var routed []string
			prev := wipeTempFile
			wipeTempFile = func(p string) error {
				routed = append(routed, p)
				return prev(p) // delegate to the real primitive
			}
			defer func() { wipeTempFile = prev }()

			cleanupTempFiles(tmp)

			if len(routed) != 1 || routed[0] != tmp {
				t.Fatalf("temp not routed through secure wipe seam (bare os.Remove?): routed=%v want=[%q]", routed, tmp)
			}
			if _, err := os.Stat(tmp); !os.IsNotExist(err) {
				t.Fatalf("temp still exists after cleanup: %v", err)
			}
		})
	}
}

// TestCleanupTempFilesWipesAllProvidedTemps proves the shared helper handles the
// real call shape from both runEncrypt and runDecrypt: a stdin staging temp AND
// a stdout staging temp are both securely wiped in one cleanup pass.
func TestCleanupTempFilesWipesAllProvidedTemps(t *testing.T) {
	dir := t.TempDir()
	stdinTemp := filepath.Join(dir, "picocrypt-stdin-a")
	stdoutTemp := filepath.Join(dir, "picocrypt-out-b")
	for _, p := range []string{stdinTemp, stdoutTemp} {
		if err := os.WriteFile(p, []byte("plaintext fragment"), 0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	var routed []string
	prev := wipeTempFile
	wipeTempFile = func(p string) error {
		routed = append(routed, p)
		return prev(p)
	}
	defer func() { wipeTempFile = prev }()

	cleanupTempFiles(stdinTemp, stdoutTemp)

	if len(routed) != 2 {
		t.Fatalf("expected both temps routed through secure wipe, got %v", routed)
	}
	for _, p := range []string{stdinTemp, stdoutTemp} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("temp %s still exists after cleanup", p)
		}
	}
}

// TestCleanupTempFilesSkipsEmptyPaths guards the "no temp was created" case:
// runEncrypt/runDecrypt pass "" when stdin/stdout buffering never ran, and the
// helper must not invoke the wipe seam (which would error on an empty path).
func TestCleanupTempFilesSkipsEmptyPaths(t *testing.T) {
	calls := 0
	prev := wipeTempFile
	wipeTempFile = func(p string) error {
		calls++
		return nil
	}
	defer func() { wipeTempFile = prev }()

	cleanupTempFiles("", "")

	if calls != 0 {
		t.Fatalf("cleanupTempFiles invoked wipe seam for empty paths: %d calls", calls)
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
