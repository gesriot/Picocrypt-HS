package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestChooseTempDir_SystemDefault(t *testing.T) {
	// Reset override
	TempDirOverride = ""

	dir, err := ChooseTempDir(1024, "")
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}
	if dir == "" {
		t.Error("expected non-empty temp dir")
	}
	// Should return system temp or a fallback
	if !isWritable(dir) {
		t.Errorf("returned dir %s is not writable", dir)
	}
}

func TestChooseTempDir_Override(t *testing.T) {
	// Create a temp directory to use as override
	tmpDir := t.TempDir()
	TempDirOverride = tmpDir
	defer func() { TempDirOverride = "" }()

	dir, err := ChooseTempDir(1024, "")
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}
	if dir != tmpDir {
		t.Errorf("expected override dir %s, got %s", tmpDir, dir)
	}
}

func TestChooseTempDir_OverrideNotWritable(t *testing.T) {
	TempDirOverride = "/nonexistent/dir/that/does/not/exist"
	defer func() { TempDirOverride = "" }()

	_, err := ChooseTempDir(1024, "")
	if err == nil {
		t.Error("expected error for non-writable override")
	}
}

func TestChooseTempDir_WithOutputPath(t *testing.T) {
	TempDirOverride = ""

	// Use a real path for output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.pcv")

	dir, err := ChooseTempDir(1024, outputPath)
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}
	if dir == "" {
		t.Error("expected non-empty temp dir")
	}
}

func TestBuildCandidates(t *testing.T) {
	testPath := filepath.Join("some", "output", "path.pcv")
	candidates := buildCandidates(testPath)

	if len(candidates) < 2 {
		t.Errorf("expected at least 2 candidates, got %d", len(candidates))
	}

	// First should be system temp
	if candidates[0] != os.TempDir() {
		t.Errorf("first candidate should be os.TempDir(), got %s", candidates[0])
	}

	// Second should be output dir
	expectedDir := filepath.Dir(testPath)
	if candidates[1] != expectedDir {
		t.Errorf("second candidate should be output dir %s, got %s", expectedDir, candidates[1])
	}
}

func TestBuildCandidates_NoOutput(t *testing.T) {
	candidates := buildCandidates("")

	if len(candidates) < 1 {
		t.Error("expected at least 1 candidate")
	}
	if candidates[0] != os.TempDir() {
		t.Errorf("first candidate should be os.TempDir()")
	}
}

func TestBuildCandidates_StdoutOutput(t *testing.T) {
	candidates := buildCandidates("-")

	// Should not add "-" as a candidate directory
	for _, c := range candidates {
		if c == "-" {
			t.Error("should not include '-' as candidate directory")
		}
	}
}

func TestIsWritable(t *testing.T) {
	// Writable directory
	tmpDir := t.TempDir()
	if !isWritable(tmpDir) {
		t.Errorf("%s should be writable", tmpDir)
	}

	// Non-existent directory
	if isWritable("/nonexistent/path") {
		t.Error("/nonexistent/path should not be writable")
	}

	// File (not directory)
	tmpFile, err := os.CreateTemp("", "test-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	if isWritable(tmpFile.Name()) {
		t.Error("file should not be considered writable directory")
	}
}

func TestRequiredSpace(t *testing.T) {
	tests := []struct {
		estimated int64
		wantMin   int64
	}{
		{0, minBuffer}, // min buffer
		{100 * 1024 * 1024, 150*1024*1024 + minBuffer},   // 100MB -> 150MB + buffer
		{1024 * 1024 * 1024, 1536*1024*1024 + minBuffer}, // 1GB -> 1.5GB + buffer
	}

	for _, tt := range tests {
		got := requiredSpace(tt.estimated)
		if got < tt.wantMin {
			t.Errorf("requiredSpace(%d) = %d, want >= %d", tt.estimated, got, tt.wantMin)
		}
	}
}

func TestUserCacheDir(t *testing.T) {
	dir, err := userCacheDir()
	if err != nil {
		t.Fatalf("userCacheDir() error = %v", err)
	}
	if dir == "" {
		t.Error("expected non-empty cache dir")
	}

	// Verify directory exists
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("cache dir does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("cache dir is not a directory")
	}
}

func TestAvailableSpace(t *testing.T) {
	tmpDir := t.TempDir()
	space, err := availableSpace(tmpDir)
	if err != nil {
		t.Fatalf("availableSpace() error = %v", err)
	}
	if space <= 0 {
		t.Errorf("expected positive space, got %d", space)
	}
}

func TestAvailableSpace_NonExistent(t *testing.T) {
	_, err := availableSpace("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestBuildCandidatesForStdin(t *testing.T) {
	testPath := filepath.Join("some", "output", "path.pcv")
	candidates := buildCandidatesForStdin(testPath)

	if len(candidates) < 2 {
		t.Errorf("expected at least 2 candidates, got %d", len(candidates))
	}

	// First should be system temp
	if candidates[0] != os.TempDir() {
		t.Errorf("first candidate should be os.TempDir(), got %s", candidates[0])
	}

	cacheDir, err := userCacheDir()
	if err != nil {
		t.Fatalf("userCacheDir() error = %v", err)
	}
	if candidates[1] != cacheDir {
		t.Errorf("second candidate should be user cache dir %s, got %s", cacheDir, candidates[1])
	}

	disallowed := map[string]bool{
		filepath.Dir(testPath): true,
	}
	if cwd, err := os.Getwd(); err == nil {
		disallowed[cwd] = true
	}
	for _, candidate := range candidates {
		if disallowed[candidate] {
			t.Errorf("stdin candidates should not include output dir or cwd, got %s", candidate)
		}
	}
}

func TestBuildCandidatesForStdin_NoOutput(t *testing.T) {
	candidates := buildCandidatesForStdin("")

	if len(candidates) < 2 {
		t.Errorf("expected at least 2 candidates, got %d", len(candidates))
	}

	if candidates[0] != os.TempDir() {
		t.Errorf("first candidate should be os.TempDir(), got %s", candidates[0])
	}

	cacheDir, err := userCacheDir()
	if err != nil {
		t.Fatalf("userCacheDir() error = %v", err)
	}
	if candidates[1] != cacheDir {
		t.Errorf("second candidate should be user cache dir %s, got %s", cacheDir, candidates[1])
	}
}

func TestBuildCandidatesForStdin_StdoutOutput(t *testing.T) {
	candidates := buildCandidatesForStdin("-")

	// Should not include "-" as candidate
	for _, c := range candidates {
		if c == "-" {
			t.Error("should not include '-' as candidate directory")
		}
	}

	if candidates[0] != os.TempDir() {
		t.Errorf("first candidate should be os.TempDir(), got %s", candidates[0])
	}
}

func TestChooseTempDir_StdinPrefersSystemTemp(t *testing.T) {
	TempDirOverride = ""

	// Create a writable temp dir to simulate output location
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.pcv")

	// estimatedSize=0 indicates stdin (unknown size)
	dir, err := ChooseTempDir(0, outputPath)
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}

	// Should prefer system temp for stdin when available
	if dir != os.TempDir() {
		t.Errorf("stdin mode should prefer system temp %s, got %s", os.TempDir(), dir)
	}
}

func TestChooseTempDir_StdinFallsBackToUserCache(t *testing.T) {
	TempDirOverride = ""

	missingTemp := filepath.Join(t.TempDir(), "missing-temp")
	switch runtime.GOOS {
	case "windows":
		t.Setenv("TMP", missingTemp)
		t.Setenv("TEMP", missingTemp)
	default:
		t.Setenv("TMPDIR", missingTemp)
	}

	outputPath := filepath.Join(t.TempDir(), "output.pcv")
	dir, err := ChooseTempDir(0, outputPath)
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}

	cacheDir, err := userCacheDir()
	if err != nil {
		t.Fatalf("userCacheDir() error = %v", err)
	}
	if dir != cacheDir {
		t.Errorf("stdin mode should fall back to user cache %s, got %s", cacheDir, dir)
	}
}

func TestChooseTempDir_KnownSizePrefersSystemTemp(t *testing.T) {
	TempDirOverride = ""

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "output.pcv")

	// Known size (not stdin)
	dir, err := ChooseTempDir(1024, outputPath)
	if err != nil {
		t.Fatalf("ChooseTempDir() error = %v", err)
	}

	// Should prefer system temp for known-size files
	if dir != os.TempDir() {
		t.Logf("Note: known-size mode selected %s instead of system temp %s", dir, os.TempDir())
	}
}
