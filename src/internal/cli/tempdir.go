package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

// TempDirOverride is set by --temp-dir flag
var TempDirOverride string

const (
	// minBuffer is extra space required beyond estimated size (10 MB)
	minBuffer int64 = 10 * 1024 * 1024
	// sizeMultiplier is the factor applied to estimated size (1.5x)
	sizeMultiplier float64 = 1.5
	// defaultEstimate for unknown stdin size (100 MB)
	defaultEstimate int64 = 100 * 1024 * 1024
	// cacheDirName is the fallback cache directory name
	cacheDirName = "picocrypt"
)

// ChooseTempDir selects an appropriate temp directory for buffering.
// Priority: --temp-dir flag > system temp > output dir > cwd > ~/.cache/picocrypt
// estimatedSize is the expected file size (0 for unknown stdin).
// outputPath is used to determine the output directory as a fallback.
func ChooseTempDir(estimatedSize int64, outputPath string) (string, error) {
	if estimatedSize <= 0 {
		estimatedSize = defaultEstimate
	}
	required := requiredSpace(estimatedSize)

	candidates := buildCandidates(outputPath)

	// Check explicit override first
	if TempDirOverride != "" {
		if isWritable(TempDirOverride) {
			space, err := availableSpace(TempDirOverride)
			if err == nil && space >= required {
				return TempDirOverride, nil
			}
			if err != nil {
				return "", fmt.Errorf("--temp-dir %s: %w", TempDirOverride, err)
			}
			return "", fmt.Errorf("--temp-dir %s: insufficient space (need %d, have %d)", TempDirOverride, required, space)
		}
		return "", fmt.Errorf("--temp-dir %s: not writable", TempDirOverride)
	}

	// Try system default first (index 0)
	systemDefault := candidates[0]
	if isWritable(systemDefault) {
		space, err := availableSpace(systemDefault)
		if err == nil && space >= required {
			return systemDefault, nil
		}
	}

	// Try fallbacks
	for _, dir := range candidates[1:] {
		if dir == "" {
			continue
		}
		if !isWritable(dir) {
			continue
		}
		space, err := availableSpace(dir)
		if err != nil || space < required {
			continue
		}
		// Warn when not using system default
		fmt.Fprintf(os.Stderr, "Warning: using %s for temp files (system temp dir has insufficient space)\n", dir)
		return dir, nil
	}

	return "", fmt.Errorf("no temp directory with sufficient space (need %d bytes)", required)
}

// buildCandidates returns temp dir candidates in priority order.
func buildCandidates(outputPath string) []string {
	candidates := []string{os.TempDir()}

	// Output directory
	if outputPath != "" && outputPath != "-" {
		candidates = append(candidates, filepath.Dir(outputPath))
	}

	// Current working directory
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}

	// User cache directory
	if cacheDir, err := userCacheDir(); err == nil {
		candidates = append(candidates, cacheDir)
	}

	return candidates
}

// userCacheDir returns platform-specific cache dir, creating it if needed.
// Linux: ~/.cache/picocrypt, macOS: ~/Library/Caches/picocrypt, Windows: %LOCALAPPDATA%\picocrypt
func userCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cacheDir := filepath.Join(base, cacheDirName)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", err
	}
	return cacheDir, nil
}

// isWritable checks if directory is writable by creating a temp file.
func isWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".picocrypt-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

// requiredSpace calculates space needed for temp file.
func requiredSpace(estimatedSize int64) int64 {
	return int64(float64(estimatedSize)*sizeMultiplier) + minBuffer
}
