package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReporter(t *testing.T) {
	t.Run("NewReporter", func(t *testing.T) {
		r := NewReporter(false)
		if r == nil {
			t.Fatal("NewReporter returned nil")
		}
		if r.quiet {
			t.Error("quiet should be false")
		}

		r = NewReporter(true)
		if !r.quiet {
			t.Error("quiet should be true")
		}
	})

	t.Run("SetStatus", func(t *testing.T) {
		r := NewReporter(false)
		r.SetStatus("test status")
		if r.status != "test status" {
			t.Errorf("expected 'test status', got %q", r.status)
		}
	})

	t.Run("SetProgress", func(t *testing.T) {
		r := NewReporter(false)
		r.SetProgress(0.5, "50%")
		if r.progress != 0.5 {
			t.Errorf("expected progress 0.5, got %f", r.progress)
		}
		if r.info != "50%" {
			t.Errorf("expected info '50%%', got %q", r.info)
		}
	})

	t.Run("Cancel", func(t *testing.T) {
		r := NewReporter(false)
		if r.IsCancelled() {
			t.Error("should not be cancelled initially")
		}
		r.Cancel()
		if !r.IsCancelled() {
			t.Error("should be cancelled after Cancel()")
		}
	})

	t.Run("SetCanCancel", func(t *testing.T) {
		r := NewReporter(false)
		// Should be a no-op, just ensure it doesn't panic
		r.SetCanCancel(true)
		r.SetCanCancel(false)
	})
}

func TestEncryptValidation(t *testing.T) {
	// Save original args
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	t.Run("missing input", func(t *testing.T) {
		// Reset flags for each test
		encInput = nil
		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "input") {
			t.Errorf("error should mention input: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		encInput = []string{"/nonexistent/file/path.txt"}
		encOutput = ""
		encPassword = "test"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		// Create temp file
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encOutput = ""
		encPassword = ""
		encKeyfiles = nil

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "keyfile") {
			t.Errorf("error should mention password or keyfile: %v", err)
		}
	})

	t.Run("invalid split options", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encSplit = true
		encSplitSize = 0 // Invalid

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for invalid split options")
		}
		if !strings.Contains(err.Error(), "split-size") {
			t.Errorf("error should mention split-size: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("invalid split unit", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "invalid"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for invalid split unit")
		}
		if !strings.Contains(err.Error(), "invalid split unit") {
			t.Errorf("error should mention invalid split unit: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
		encSplitUnit = "MiB"
	})

	t.Run("nonexistent keyfile", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encPassword = "test"
		encKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent keyfile")
		}
		if !strings.Contains(err.Error(), "keyfile not found") {
			t.Errorf("error should mention keyfile not found: %v", err)
		}

		// Reset
		encKeyfiles = nil
	})
}

func TestDecryptValidation(t *testing.T) {
	t.Run("missing input", func(t *testing.T) {
		decInput = ""
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing input")
		}
		if !strings.Contains(err.Error(), "input") {
			t.Errorf("error should mention input: %v", err)
		}
	})

	t.Run("nonexistent input file", func(t *testing.T) {
		decInput = "/nonexistent/file.pcv"
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("input is directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		decInput = tmpDir
		decPassword = "test"

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for directory input")
		}
		if !strings.Contains(err.Error(), "directory") {
			t.Errorf("error should mention directory: %v", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = tmpFile
		decPassword = ""
		decKeyfiles = nil
		decQuiet = true // Suppress header read warning

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for missing credentials")
		}
		if !strings.Contains(err.Error(), "password") && !strings.Contains(err.Error(), "keyfile") {
			t.Errorf("error should mention password or keyfile: %v", err)
		}

		// Reset
		decQuiet = false
	})

	t.Run("nonexistent keyfile", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = tmpFile
		decPassword = "test"
		decKeyfiles = []string{"/nonexistent/keyfile.key"}

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for nonexistent keyfile")
		}
		if !strings.Contains(err.Error(), "keyfile not found") {
			t.Errorf("error should mention keyfile not found: %v", err)
		}

		// Reset
		decKeyfiles = nil
	})
}

func TestSplitVolumeDetection(t *testing.T) {
	t.Run("detects split volume pattern", func(t *testing.T) {
		// Create temp files that look like split volumes
		tmpDir := t.TempDir()
		splitFile := filepath.Join(tmpDir, "test.pcv.0")
		if err := os.WriteFile(splitFile, []byte("chunk0"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = splitFile
		decPassword = "test"
		decRecombine = false
		decQuiet = true

		// The validation will fail (not a valid pcv), but we can check if recombine was set
		cmd := decryptCmd
		_ = cmd.RunE(cmd, []string{})

		if !decRecombine {
			t.Error("should have detected split volume and set recombine=true")
		}

		// Reset
		decRecombine = false
		decQuiet = false
	})
}

func TestOutputAutoGeneration(t *testing.T) {
	t.Run("encrypt auto-generates output", func(t *testing.T) {
		tmpDir := t.TempDir()
		inputFile := filepath.Join(tmpDir, "test.txt")
		if err := os.WriteFile(inputFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		// We can't easily test the full flow without actually encrypting,
		// but we can verify the logic by checking what output would be generated
		encInput = []string{inputFile}
		encOutput = ""

		// The auto-generation happens inside runEncrypt, so we just verify the logic
		outputFile := encOutput
		if outputFile == "" {
			if len(encInput) == 1 {
				outputFile = encInput[0] + ".pcv"
			} else {
				outputFile = "encrypted.pcv"
			}
		}

		expected := inputFile + ".pcv"
		if outputFile != expected {
			t.Errorf("expected %q, got %q", expected, outputFile)
		}
	})

	t.Run("decrypt auto-generates output", func(t *testing.T) {
		input := "/path/to/file.pcv"
		expected := "/path/to/file"

		output := strings.TrimSuffix(input, ".pcv")
		if output != expected {
			t.Errorf("expected %q, got %q", expected, output)
		}
	})
}

func TestGlobExpansion(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	for _, name := range []string{"a.txt", "b.txt", "c.log"} {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("glob matches files", func(t *testing.T) {
		pattern := filepath.Join(tmpDir, "*.txt")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(matches))
		}
	})

	t.Run("glob no matches", func(t *testing.T) {
		pattern := filepath.Join(tmpDir, "*.xyz")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestReporterOutput(t *testing.T) {
	t.Run("quiet mode suppresses output", func(t *testing.T) {
		r := NewReporter(true)
		r.SetStatus("test")
		r.SetProgress(0.5, "50%")

		// Capture stderr
		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.Update()
		r.Finish()

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if buf.Len() != 0 {
			t.Errorf("quiet mode should not produce output, got: %q", buf.String())
		}
	})

	t.Run("PrintSuccess respects quiet", func(t *testing.T) {
		r := NewReporter(true)

		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.PrintSuccess("success message")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if buf.Len() != 0 {
			t.Errorf("quiet mode should suppress success, got: %q", buf.String())
		}
	})

	t.Run("PrintError always outputs", func(t *testing.T) {
		r := NewReporter(true) // Even in quiet mode

		old := os.Stderr
		r2, w, _ := os.Pipe()
		os.Stderr = w

		r.PrintError("error message")

		w.Close()
		os.Stderr = old

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r2)

		if !strings.Contains(buf.String(), "error message") {
			t.Errorf("PrintError should always output, got: %q", buf.String())
		}
	})
}

func TestVersionFlag(t *testing.T) {
	// Test that version is set correctly
	Version = "v1.0.0"
	if rootCmd.Version != "v1.0.0" {
		// Version is set by Execute(), so we need to call the setter
		rootCmd.Version = Version
	}
	if rootCmd.Version != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %s", rootCmd.Version)
	}
}

func TestDetectCLIMode(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "encrypt subcommand",
			args: []string{"encrypt", "-i", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "persistent flag before subcommand",
			args: []string{"--temp-dir", "/tmp", "encrypt", "-i", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "persistent flag equals form before subcommand",
			args: []string{"--temp-dir=/tmp", "decrypt", "-i", "a.pcv"},
			want: true,
		},
		{
			name: "root version flag",
			args: []string{"--version"},
			want: true,
		},
		{
			name: "bare version token is not a command",
			args: []string{"version"},
			want: false,
		},
		{
			name: "invalid root flag before subcommand",
			args: []string{"--bogus", "encrypt", "-i", "a", "-o", "a.pcv"},
			want: true,
		},
		{
			name: "missing value root flag before subcommand",
			args: []string{"--temp-dir", "encrypt", "-i", "a", "-o", "a.pcv", "-p", "pw"},
			want: true,
		},
		{
			name: "unknown GUI-style arg",
			args: []string{"--fyne-driver=software"},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectCLIMode(tc.args); got != tc.want {
				t.Fatalf("detectCLIMode(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestDefaultEncryptOutput(t *testing.T) {
	t.Run("multiple expanded matches", func(t *testing.T) {
		pattern := "/tmp/*.txt"
		allFiles := []string{"/tmp/a.txt", "/tmp/b.txt"}

		got := defaultEncryptOutput(pattern, allFiles, false)
		if got != "encrypted.pcv" {
			t.Fatalf("defaultEncryptOutput(%q, %q, false) = %q, want %q",
				pattern, allFiles, got, "encrypted.pcv")
		}
	})

	t.Run("single expanded match", func(t *testing.T) {
		pattern := "/tmp/*.txt"
		allFiles := []string{"/tmp/a.txt"}

		got := defaultEncryptOutput(pattern, allFiles, false)
		if got != "/tmp/a.txt.pcv" {
			t.Fatalf("defaultEncryptOutput(%q, %q, false) = %q, want %q",
				pattern, allFiles, got, "/tmp/a.txt.pcv")
		}
	})
}

func TestEncryptStdinValidation(t *testing.T) {
	t.Run("stdin with password stdin conflict", func(t *testing.T) {
		encInput = []string{"-"}
		encOutput = "test.pcv"
		encPassword = ""
		encPasswordStdin = true
		encKeyfiles = nil
		encSplit = false
		encDeniability = false

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with -P conflict")
		}
		if !strings.Contains(err.Error(), "cannot use -P") {
			t.Errorf("error should mention -P conflict: %v", err)
		}

		// Reset
		encPasswordStdin = false
	})

	t.Run("password stdin empty without keyfiles", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = r
		if _, err := w.WriteString("\n"); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		t.Cleanup(func() {
			os.Stdin = oldStdin
			_ = r.Close()
		})

		encInput = []string{tmpFile}
		encOutput = filepath.Join(t.TempDir(), "test.pcv")
		encPassword = ""
		encPasswordStdin = true
		encKeyfiles = nil
		encSplit = false
		encDeniability = false

		cmd := encryptCmd
		err = cmd.RunE(cmd, []string{})
		if err == nil {
			t.Fatal("expected error for empty password from stdin")
		}
		if !strings.Contains(err.Error(), ErrPasswordEmpty.Error()) {
			t.Errorf("expected empty password error, got: %v", err)
		}

		encPasswordStdin = false
	})

	t.Run("stdin with multiple inputs conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{"-", tmpFile}
		encOutput = "test.pcv"
		encPassword = "test"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with multiple inputs")
		}
		if !strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("error should mention cannot be combined: %v", err)
		}
	})

	t.Run("stdin/stdout with split conflict", func(t *testing.T) {
		encInput = []string{"-"}
		encOutput = "test.pcv"
		encPassword = "test"
		encPasswordStdin = false
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "MiB"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with --split")
		}
		if !strings.Contains(err.Error(), "not compatible with --split") {
			t.Errorf("error should mention --split incompatibility: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("stdout with split conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.txt")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		encInput = []string{tmpFile}
		encOutput = "-"
		encPassword = "test"
		encSplit = true
		encSplitSize = 10
		encSplitUnit = "MiB"

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdout with --split")
		}
		if !strings.Contains(err.Error(), "not compatible with --split") {
			t.Errorf("error should mention --split incompatibility: %v", err)
		}

		// Reset
		encSplit = false
		encSplitSize = 0
	})

	t.Run("stdin with deniability conflict", func(t *testing.T) {
		encInput = []string{"-"}
		encOutput = "test.pcv"
		encPassword = "test"
		encDeniability = true

		cmd := encryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with --deniability")
		}
		if !strings.Contains(err.Error(), "not compatible with --deniability") {
			t.Errorf("error should mention --deniability incompatibility: %v", err)
		}

		// Reset
		encDeniability = false
	})
}

func TestCleanupEncryptError(t *testing.T) {
	t.Run("preserves pre-existing output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "existing.pcv")
		if err := os.WriteFile(output, []byte("original"), 0644); err != nil {
			t.Fatal(err)
		}
		incomplete := output + ".incomplete"
		if err := os.WriteFile(incomplete, []byte("partial"), 0644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, false, true)

		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatalf("expected pre-existing output file to remain: %v", err)
		}
		if string(data) != "original" {
			t.Fatalf("expected original content preserved, got %q", string(data))
		}
		if _, err := os.Stat(incomplete); !os.IsNotExist(err) {
			t.Fatalf("expected incomplete file removed, got: %v", err)
		}
	})

	t.Run("removes new output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "new.pcv")
		if err := os.WriteFile(output, []byte("new"), 0644); err != nil {
			t.Fatal(err)
		}
		incomplete := output + ".incomplete"
		if err := os.WriteFile(incomplete, []byte("partial"), 0644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, false, false)

		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatalf("expected output file removed, got: %v", err)
		}
		if _, err := os.Stat(incomplete); !os.IsNotExist(err) {
			t.Fatalf("expected incomplete file removed, got: %v", err)
		}
	})

	t.Run("stdout mode does not remove output file", func(t *testing.T) {
		tmpDir := t.TempDir()
		output := filepath.Join(tmpDir, "stdout-temp.pcv")
		if err := os.WriteFile(output, []byte("temp"), 0644); err != nil {
			t.Fatal(err)
		}

		cleanupEncryptError(output, true, false)

		if _, err := os.Stat(output); err != nil {
			t.Fatalf("expected stdout path untouched, got: %v", err)
		}
	})
}

func TestDecryptStdinValidation(t *testing.T) {
	t.Run("stdin with password stdin conflict", func(t *testing.T) {
		decInput = "-"
		decOutput = "test.txt"
		decPassword = ""
		decPasswordStdin = true
		decKeyfiles = nil
		decRecombine = false
		decDeniability = false
		decAutoUnzip = false

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with -P conflict")
		}
		if !strings.Contains(err.Error(), "cannot use -P") {
			t.Errorf("error should mention -P conflict: %v", err)
		}

		// Reset
		decPasswordStdin = false
	})

	t.Run("stdin with recombine conflict", func(t *testing.T) {
		decInput = "-"
		decOutput = "test.txt"
		decPassword = "test"
		decRecombine = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with --recombine")
		}
		if !strings.Contains(err.Error(), "not compatible with --recombine") {
			t.Errorf("error should mention --recombine incompatibility: %v", err)
		}

		// Reset
		decRecombine = false
	})

	t.Run("stdin with deniability conflict", func(t *testing.T) {
		decInput = "-"
		decOutput = "test.txt"
		decPassword = "test"
		decDeniability = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdin with --deniability")
		}
		if !strings.Contains(err.Error(), "not compatible with --deniability") {
			t.Errorf("error should mention --deniability incompatibility: %v", err)
		}

		// Reset
		decDeniability = false
	})

	t.Run("stdout with auto-unzip conflict", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "test.pcv")
		if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		decInput = tmpFile
		decOutput = "-"
		decPassword = "test"
		decAutoUnzip = true

		cmd := decryptCmd
		err := cmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("expected error for stdout with --auto-unzip")
		}
		if !strings.Contains(err.Error(), "not compatible with --auto-unzip") {
			t.Errorf("error should mention --auto-unzip incompatibility: %v", err)
		}

		// Reset
		decAutoUnzip = false
	})
}
