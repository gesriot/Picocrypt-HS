package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Integration tests for stdin/stdout functionality.
// These tests build and run the actual CLI binary to verify end-to-end behavior.

func cliIntegrationEnabled() bool {
	return os.Getenv("PICOCRYPT_RUN_CLI_INTEGRATION") == "1"
}

func requireCLIIntegration(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if !cliIntegrationEnabled() {
		t.Skip("set PICOCRYPT_RUN_CLI_INTEGRATION=1 to run CLI integration tests")
	}
}

func TestStdinStdoutIntegration(t *testing.T) {
	requireCLIIntegration(t)

	// Build CLI binary
	tmpDir := t.TempDir()
	binaryName := "picocrypt-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	// Get absolute path to src directory (parent of internal/cli)
	srcDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("getting source dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "cli", "-o", binaryPath, "./cmd/picocrypt")
	cmd.Dir = srcDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building binary: %v\nOutput: %s", err, output)
	}

	testPassword := "testpassword123"

	t.Run("stdin encrypt to file", func(t *testing.T) {
		inputData := []byte("secret data for stdin encryption test")
		outputFile := filepath.Join(tmpDir, "stdin-encrypt.pcv")

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", outputFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = bytes.NewReader(inputData)

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("stdin encrypt failed: %v\nOutput: %s", err, output)
		}

		// Verify output file exists and has content
		info, err := os.Stat(outputFile)
		if err != nil {
			t.Fatalf("output file not found: %v", err)
		}
		if info.Size() == 0 {
			t.Error("output file is empty")
		}
		if info.Size() <= int64(len(inputData)) {
			t.Error("output file should be larger than input (has header)")
		}

		// Decrypt and verify
		decryptedFile := filepath.Join(tmpDir, "stdin-decrypted")
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", outputFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("decrypt verification failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("file encrypt to stdout", func(t *testing.T) {
		inputData := []byte("secret data for stdout encryption test")
		inputFile := filepath.Join(tmpDir, "stdout-input.txt")
		if err := os.WriteFile(inputFile, inputData, 0644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", inputFile,
			"-o", "-",
			"-p", testPassword,
		)

		encrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("stdout encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdout encrypt failed: %v", err)
		}

		if len(encrypted) == 0 {
			t.Error("no data written to stdout")
		}
		if len(encrypted) <= len(inputData) {
			t.Error("stdout output should be larger than input (has header)")
		}

		// Save and decrypt to verify
		encryptedFile := filepath.Join(tmpDir, "stdout-test.pcv")
		if err := os.WriteFile(encryptedFile, encrypted, 0644); err != nil {
			t.Fatal(err)
		}

		decryptedFile := filepath.Join(tmpDir, "stdout-decrypted")
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", encryptedFile,
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("decrypt verification failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin to stdout full pipeline", func(t *testing.T) {
		inputData := []byte("full pipeline test data through stdin to stdout")

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = bytes.NewReader(inputData)

		encrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("stdin->stdout encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdin->stdout encrypt failed: %v", err)
		}

		if len(encrypted) == 0 {
			t.Fatal("no encrypted data produced")
		}

		// Decrypt via stdin->stdout
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", "-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = bytes.NewReader(encrypted)

		decrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("stdin->stdout decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdin->stdout decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("round-trip content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("stdin decrypt from file", func(t *testing.T) {
		inputData := []byte("data to decrypt from stdin")
		encryptedFile := filepath.Join(tmpDir, "for-stdin-decrypt.pcv")

		// Create encrypted file first
		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = bytes.NewReader(inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encryption failed: %v\nOutput: %s", err, output)
		}

		// Read encrypted file to feed via stdin
		encrypted, err := os.ReadFile(encryptedFile)
		if err != nil {
			t.Fatal(err)
		}

		decryptedFile := filepath.Join(tmpDir, "stdin-decrypt-output")
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", "-",
			"-o", decryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = bytes.NewReader(encrypted)

		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("stdin decrypt failed: %v\nOutput: %s", err, output)
		}

		decrypted, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("reading decrypted file: %v", err)
		}
		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("file decrypt to stdout", func(t *testing.T) {
		inputData := []byte("data to decrypt to stdout")
		encryptedFile := filepath.Join(tmpDir, "for-stdout-decrypt.pcv")

		// Create encrypted file
		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", encryptedFile,
			"-p", testPassword,
			"-y",
		)
		cmd.Stdin = bytes.NewReader(inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encryption failed: %v\nOutput: %s", err, output)
		}

		// Decrypt to stdout
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", encryptedFile,
			"-o", "-",
			"-p", testPassword,
		)

		decrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("stdout decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("stdout decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("decrypted content mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("large data through pipeline", func(t *testing.T) {
		// Test with 1 MiB of data
		inputData := make([]byte, 1024*1024)
		for i := range inputData {
			inputData[i] = byte(i % 256)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = bytes.NewReader(inputData)

		encrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("large data encrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("large data encrypt failed: %v", err)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			"-i", "-",
			"-o", "-",
			"-p", testPassword,
		)
		cmd.Stdin = bytes.NewReader(encrypted)

		decrypted, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				t.Fatalf("large data decrypt failed: %v\nStderr: %s", err, exitErr.Stderr)
			}
			t.Fatalf("large data decrypt failed: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Error("large data round-trip content mismatch")
		}
	})

	t.Run("piped commands simulate", func(t *testing.T) {
		// Simulate: echo "data" | encrypt | decrypt
		inputData := []byte("piped command simulation test\n")

		// Encrypt
		encCmd := exec.Command(binaryPath, "encrypt", "-i", "-", "-o", "-", "-p", testPassword)
		encCmd.Stdin = bytes.NewReader(inputData)
		encrypted, err := encCmd.Output()
		if err != nil {
			t.Fatalf("pipe encrypt: %v", err)
		}

		// Decrypt
		decCmd := exec.Command(binaryPath, "decrypt", "-i", "-", "-o", "-", "-p", testPassword)
		decCmd.Stdin = bytes.NewReader(encrypted)
		decrypted, err := decCmd.Output()
		if err != nil {
			t.Fatalf("pipe decrypt: %v", err)
		}

		if !bytes.Equal(decrypted, inputData) {
			t.Errorf("pipe round-trip mismatch\ngot:  %q\nwant: %q", decrypted, inputData)
		}
	})

	t.Run("auto-unzip works with auto-generated output path", func(t *testing.T) {
		inputA := filepath.Join(tmpDir, "auto-unzip-a.txt")
		inputB := filepath.Join(tmpDir, "auto-unzip-b.txt")
		if err := os.WriteFile(inputA, []byte("alpha"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inputB, []byte("bravo"), 0644); err != nil {
			t.Fatal(err)
		}

		volumePath := filepath.Join(tmpDir, "auto-unzip.pcv")
		cmd := exec.Command(binaryPath, "encrypt",
			"-i", inputA,
			"-i", inputB,
			"-o", volumePath,
			"-p", testPassword,
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("multi-file encrypt failed: %v\nOutput: %s", err, output)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			"-i", volumePath,
			"-p", testPassword,
			"-y",
			"--auto-unzip",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("auto-unzip decrypt failed: %v\nOutput: %s", err, output)
		}

		extractedDir := filepath.Join(tmpDir, "auto-unzip")
		info, err := os.Stat(extractedDir)
		if err != nil {
			t.Fatalf("expected extracted directory %q: %v", extractedDir, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %q to be a directory after auto-unzip", extractedDir)
		}

		if _, err := os.Stat(filepath.Join(extractedDir, filepath.Base(inputA))); err != nil {
			t.Fatalf("missing extracted file %q: %v", filepath.Base(inputA), err)
		}
		if _, err := os.Stat(filepath.Join(extractedDir, filepath.Base(inputB))); err != nil {
			t.Fatalf("missing extracted file %q: %v", filepath.Base(inputB), err)
		}
	})
}

func TestStdinStdoutErrorCases(t *testing.T) {
	requireCLIIntegration(t)

	// Build CLI binary
	tmpDir := t.TempDir()
	binaryName := "picocrypt-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	srcDir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("getting source dir: %v", err)
	}

	cmd := exec.Command("go", "build", "-tags", "cli", "-o", binaryPath, "./cmd/picocrypt")
	cmd.Dir = srcDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building binary: %v\nOutput: %s", err, output)
	}

	t.Run("stdin with -P conflicts", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", filepath.Join(tmpDir, "out.pcv"),
			"-P",
		)
		cmd.Stdin = bytes.NewReader([]byte("test"))

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -i - with -P")
		}
		if !bytes.Contains(output, []byte("cannot use -P")) {
			t.Errorf("error should mention -P conflict, got: %s", output)
		}
	})

	t.Run("stdout with --split conflicts", func(t *testing.T) {
		inputFile := filepath.Join(tmpDir, "split-test.txt")
		if err := os.WriteFile(inputFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", inputFile,
			"-o", "-",
			"-p", "test",
			"--split",
			"--split-size", "10",
		)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -o - with --split")
		}
		if !bytes.Contains(output, []byte("not compatible with --split")) {
			t.Errorf("error should mention --split conflict, got: %s", output)
		}
	})

	t.Run("stdout decrypt with --auto-unzip conflicts", func(t *testing.T) {
		// Create a valid encrypted file first
		inputFile := filepath.Join(tmpDir, "unzip-test.txt")
		encFile := filepath.Join(tmpDir, "unzip-test.pcv")
		if err := os.WriteFile(inputFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		cmd := exec.Command(binaryPath, "encrypt",
			"-i", inputFile,
			"-o", encFile,
			"-p", "test",
			"-y",
		)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("setup encrypt failed: %v\nOutput: %s", err, output)
		}

		cmd = exec.Command(binaryPath, "decrypt",
			"-i", encFile,
			"-o", "-",
			"-p", "test",
			"--auto-unzip",
		)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for -o - with --auto-unzip")
		}
		if !bytes.Contains(output, []byte("not compatible with --auto-unzip")) {
			t.Errorf("error should mention --auto-unzip conflict, got: %s", output)
		}
	})

	t.Run("wrong password via stdin decrypt fails", func(t *testing.T) {
		inputData := []byte("secret")
		encFile := filepath.Join(tmpDir, "wrong-pw.pcv")

		// Encrypt with correct password
		cmd := exec.Command(binaryPath, "encrypt",
			"-i", "-",
			"-o", encFile,
			"-p", "correctpassword",
			"-y",
		)
		cmd.Stdin = bytes.NewReader(inputData)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("encrypt failed: %v\nOutput: %s", err, output)
		}

		// Try decrypt with wrong password
		encrypted, _ := os.ReadFile(encFile)
		cmd = exec.Command(binaryPath, "decrypt",
			"-i", "-",
			"-o", "-",
			"-p", "wrongpassword",
		)
		cmd.Stdin = bytes.NewReader(encrypted)

		output, err := cmd.CombinedOutput()
		if err == nil {
			t.Error("expected error for wrong password")
		}
		// Should fail with auth error
		if !bytes.Contains(output, []byte("incorrect")) && !bytes.Contains(output, []byte("failed")) {
			t.Logf("Output: %s", output)
		}
	})
}
