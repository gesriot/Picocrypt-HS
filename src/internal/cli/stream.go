package cli

import (
	"fmt"
	"io"
	"os"
)

// cleanupTempFiles best-effort removes the stdin/stdout staging temps created
// for a CLI encrypt/decrypt run. Empty paths are skipped (no temp was created
// for that direction). Errors are intentionally ignored: cleanup is best-effort
// and must never mask the operation's real result.
func cleanupTempFiles(paths ...string) {
	for _, p := range paths {
		if p != "" {
			_ = os.Remove(p)
		}
	}
}

// IsStdin returns true if the path indicates stdin ("-")
func IsStdin(path string) bool {
	return path == "-"
}

// IsStdout returns true if the path indicates stdout ("-")
func IsStdout(path string) bool {
	return path == "-"
}

// BufferStdinToTemp copies stdin to a temp file and returns the path.
// outputPath is used to determine fallback temp directories.
// Caller is responsible for removing the temp file.
func BufferStdinToTemp(outputPath string) (string, error) {
	// Choose temp directory with space checking
	tempDir, err := ChooseTempDir(0, outputPath) // 0 = unknown size, use default estimate
	if err != nil {
		return "", fmt.Errorf("selecting temp directory: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, "picocrypt-stdin-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Set restrictive permissions
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("setting temp file permissions: %w", err)
	}

	_, err = io.Copy(tmp, os.Stdin)
	if err != nil {
		_ = tmp.Close()
		// This error path returns "", so the caller cannot clean up the buffered
		// stdin bytes; remove them here.
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("buffering stdin: %w", err)
	}

	if err := tmp.Close(); err != nil {
		// The buffered stdin bytes are on disk and the caller cannot reach this
		// path; remove them here.
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	return tmpPath, nil
}

// StreamFileToStdout copies a file to stdout.
func StreamFileToStdout(path string) error {
	// #nosec G304 -- path is temp file created by this package
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file for stdout: %w", err)
	}
	defer func() { _ = f.Close() }()

	_, err = io.Copy(os.Stdout, f)
	if err != nil {
		return fmt.Errorf("streaming to stdout: %w", err)
	}

	return nil
}

// CreateTempOutput creates a temp file for output.
// estimatedSize is the expected output size (0 for unknown).
// Caller is responsible for removing the temp file.
func CreateTempOutput(estimatedSize int64) (string, error) {
	// Choose temp directory with space checking
	tempDir, err := ChooseTempDir(estimatedSize, "")
	if err != nil {
		return "", fmt.Errorf("selecting temp directory: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, "picocrypt-out-*")
	if err != nil {
		return "", fmt.Errorf("creating temp output file: %w", err)
	}
	tmpPath := tmp.Name()

	// Set restrictive permissions
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("setting temp file permissions: %w", err)
	}

	// Close immediately - volume package will reopen
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	return tmpPath, nil
}
