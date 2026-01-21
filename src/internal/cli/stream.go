package cli

import (
	"fmt"
	"io"
	"os"
)

// IsStdin returns true if the path indicates stdin ("-")
func IsStdin(path string) bool {
	return path == "-"
}

// IsStdout returns true if the path indicates stdout ("-")
func IsStdout(path string) bool {
	return path == "-"
}

// BufferStdinToTemp copies stdin to a temp file and returns the path.
// Caller is responsible for removing the temp file.
func BufferStdinToTemp() (string, error) {
	tmp, err := os.CreateTemp("", "picocrypt-stdin-*")
	if err != nil {
		return "", fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Set restrictive permissions
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("setting temp file permissions: %w", err)
	}

	_, err = io.Copy(tmp, os.Stdin)
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("buffering stdin: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	return tmpPath, nil
}

// StreamFileToStdout copies a file to stdout.
func StreamFileToStdout(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file for stdout: %w", err)
	}
	defer f.Close()

	_, err = io.Copy(os.Stdout, f)
	if err != nil {
		return fmt.Errorf("streaming to stdout: %w", err)
	}

	return nil
}

// CreateTempOutput creates a temp file for output.
// Caller is responsible for removing the temp file.
func CreateTempOutput() (string, error) {
	tmp, err := os.CreateTemp("", "picocrypt-out-*")
	if err != nil {
		return "", fmt.Errorf("creating temp output file: %w", err)
	}
	tmpPath := tmp.Name()

	// Set restrictive permissions
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("setting temp file permissions: %w", err)
	}

	// Close immediately - volume package will reopen
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	return tmpPath, nil
}
