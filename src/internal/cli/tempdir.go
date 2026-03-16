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
// For known-size files: system temp > output dir > cwd > ~/.cache/picocrypt
// For stdin (size=0): user cache > system temp
// estimatedSize is the expected file size (0 for unknown stdin).
// outputPath is used to determine the output directory as a fallback.
func ChooseTempDir(estimatedSize int64, outputPath string) (string, error) {
	isStdin := estimatedSize == 0

	if estimatedSize <= 0 {
		estimatedSize = defaultEstimate
	}
	required := requiredSpace(estimatedSize)

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

	// For stdin: prefer user-scoped temp/cache locations only.
	var candidates []string
	if isStdin {
		candidates = buildCandidatesForStdin(outputPath)
	} else {
		candidates = buildCandidates(outputPath)
	}

	// Try candidates in order
	systemTemp := os.TempDir()
	for _, dir := range candidates {
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
		// Warn when not using system default (unless stdin mode where it's expected)
		if !isStdin && dir != systemTemp {
			fmt.Fprintf(os.Stderr, "Warning: using %s for temp files (system temp dir has insufficient space)\n", dir)
		}
		return dir, nil
	}

	return "", fmt.Errorf("no temp directory with sufficient space (need %d bytes)", required)
}

// buildCandidates returns temp dir candidates in priority order.
// For known-size files: system temp first (fast), then fallbacks.
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

// buildCandidatesForStdin returns user-scoped candidates for stdin buffering.
// Prefer the user cache before system temp so stdin plaintext avoids shared temp
// locations when possible. Output dir/CWD are intentionally excluded.
func buildCandidatesForStdin(outputPath string) []string {
	_ = outputPath
	if cacheDir, err := userCacheDir(); err == nil {
		return []string{cacheDir, os.TempDir()}
	}

	return []string{os.TempDir()}
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
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// requiredSpace calculates space needed for temp file.
func requiredSpace(estimatedSize int64) int64 {
	return int64(float64(estimatedSize)*sizeMultiplier) + minBuffer
}
