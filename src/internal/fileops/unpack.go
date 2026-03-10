package fileops

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Picocrypt-NG/internal/util"
)

// UnpackOptions configures archive extraction
type UnpackOptions struct {
	ZipPath    string // Path to .zip file
	ExtractDir string // Directory to extract to (empty = same as zip, minus .zip)
	SameLevel  bool   // Extract to same directory as zip (not a subdirectory)
	Progress   ProgressFunc
	Status     StatusFunc
	Cancel     CancelFunc // Cancellation check callback (optional)
}

// normalizeZipPath normalizes a path from a zip file by converting all separators
// to the platform-appropriate separator. This handles cross-platform zip files.
func normalizeZipPath(zipPath string) string {
	// Replace all backslashes with forward slashes first
	normalized := strings.ReplaceAll(zipPath, "\\", "/")
	// Then convert to platform-specific separators
	return filepath.FromSlash(normalized)
}

// isValidExtractionPath checks if the output path is within the extraction directory.
// This prevents zip slip attacks where malicious archives contain paths like ../../etc/passwd
// while allowing legitimate filenames with double dots like "file..txt".
func isValidExtractionPath(outPath, extractDir string) bool {
	// Clean both paths to resolve any .. segments
	cleanOut := filepath.Clean(outPath)
	cleanBase := filepath.Clean(extractDir)

	// Get the relative path from extractDir to outPath
	rel, err := filepath.Rel(cleanBase, cleanOut)
	if err != nil {
		return false
	}

	// If the relative path starts with "..", it's trying to escape
	// the extraction directory (path traversal attack)
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}

func prepareExtractionPath(extractDir, normalizedName string, isDir bool) (string, error) {
	relPath := filepath.Clean(normalizedName)
	if !filepath.IsLocal(relPath) {
		return "", errors.New("potentially malicious zip item path")
	}

	outPath := filepath.Join(extractDir, relPath)
	if !isValidExtractionPath(outPath, extractDir) {
		return "", errors.New("potentially malicious zip item path")
	}

	current := filepath.Clean(extractDir)
	parts := strings.Split(relPath, string(filepath.Separator))
	for i, part := range parts {
		next := filepath.Join(current, part)
		isLast := i == len(parts)-1

		info, err := os.Lstat(next)
		switch {
		case os.IsNotExist(err):
			if !isLast || isDir {
				if err := os.Mkdir(next, 0700); err != nil {
					return "", fmt.Errorf("create directory %s: %w", next, err)
				}
			}
		case err != nil:
			return "", err
		case info.Mode()&os.ModeSymlink != 0:
			return "", fmt.Errorf("refusing to follow symlink during extraction: %s", next)
		case !info.IsDir() && (!isLast || isDir):
			return "", fmt.Errorf("path exists as file: %s", next)
		case isLast && !isDir && info.IsDir():
			return "", fmt.Errorf("path exists as directory: %s", next)
		}

		current = next
	}

	return outPath, nil
}

// Unpack extracts a zip archive to the specified directory.
func Unpack(opts UnpackOptions) (retErr error) {
	reader, err := zip.OpenReader(opts.ZipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer func() {
		if err := reader.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close zip reader: %w", err)
		}
	}()

	// Calculate total uncompressed size with overflow protection
	var totalSize int64
	for _, f := range reader.File {
		size, ok := util.SafeUint64ToInt64(f.UncompressedSize64)
		if !ok {
			return fmt.Errorf("file %s: uncompressed size exceeds int64 max", f.Name)
		}
		if totalSize > math.MaxInt64-size {
			return errors.New("total uncompressed size exceeds int64 max")
		}
		totalSize += size
	}

	// Determine extraction directory
	extractDir := opts.ExtractDir
	if extractDir == "" {
		if opts.SameLevel {
			extractDir = filepath.Dir(opts.ZipPath)
		} else {
			extractDir = filepath.Join(
				filepath.Dir(opts.ZipPath),
				strings.TrimSuffix(filepath.Base(opts.ZipPath), ".zip"),
			)
		}
	}

	// Create the extraction directory if SameLevel is false
	// (when SameLevel is true, extractDir is the parent dir which should already exist)
	if !opts.SameLevel {
		// Check if extractDir exists as a file or symlink (not a real directory)
		if info, err := os.Lstat(extractDir); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("cannot extract to %s: path exists as a symlink", extractDir)
			}
			if !info.IsDir() {
				return fmt.Errorf("cannot extract to %s: path exists as a file (not a directory). Enable 'Same level' option or move/rename the existing file", extractDir)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat extraction directory %s: %w", extractDir, err)
		}

		if err := os.MkdirAll(extractDir, 0700); err != nil {
			return fmt.Errorf("create extraction directory %s: %w", extractDir, err)
		}
	}

	// First pass: create all directories and cache normalized paths
	// Cache normalized paths to avoid redundant normalization in second pass
	normalizedPaths := make(map[*zip.File]string, len(reader.File))
	for _, f := range reader.File {
		// Normalize and validate path to prevent zip slip attacks
		normalizedName := normalizeZipPath(f.Name)
		outPath, err := prepareExtractionPath(extractDir, normalizedName, f.FileInfo().IsDir())
		if err != nil {
			return err
		}

		// Cache the output path for second pass
		normalizedPaths[f] = outPath

		// Directory entries are created by prepareExtractionPath().
	}

	// Second pass: extract files
	// Note: File handles are closed manually at the end of each iteration (not using defer)
	// to prevent file descriptor exhaustion when extracting large archives with many files.
	// Using defer here would accumulate all file handles until function exit.
	var done int64
	startTime := time.Now()

	for i, f := range reader.File {
		// Check for cancellation between files
		if opts.Cancel != nil && opts.Cancel() {
			return errors.New("operation cancelled")
		}

		if f.FileInfo().IsDir() {
			continue
		}

		// Retrieve pre-validated output path from cache
		outPath := normalizedPaths[f]

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", f.Name, err)
		}

		dstFile, err := CreateSecureNoSymlink(outPath)
		if err != nil {
			_ = fileInArchive.Close()
			return fmt.Errorf("create %s: %w", outPath, err)
		}

		// Decompression bomb protection
		compressedSize, ok := util.SafeUint64ToInt64(f.CompressedSize64)
		if !ok {
			_ = dstFile.Close()
			_ = fileInArchive.Close()
			return fmt.Errorf("file %s: compressed size exceeds int64 max", f.Name)
		}
		// Overflow-safe ratio calculation: check before multiply
		var maxBytes int64
		if compressedSize > math.MaxInt64/util.MaxDecompressRatio {
			maxBytes = math.MaxInt64 // allow: ratio can't overflow, trust content
		} else {
			maxBytes = compressedSize * util.MaxDecompressRatio
		}
		// Floor for small compressed files to avoid false positives
		if maxBytes < util.MiB {
			maxBytes = util.MiB
		}

		var written int64
		buf := make([]byte, util.MiB)
		for {
			// Check for cancellation during file extraction
			if opts.Cancel != nil && opts.Cancel() {
				_ = dstFile.Close()
				_ = fileInArchive.Close()
				_ = os.Remove(outPath)
				return errors.New("operation cancelled")
			}

			n, readErr := fileInArchive.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > maxBytes {
					_ = dstFile.Close()
					_ = fileInArchive.Close()
					_ = os.Remove(outPath)
					return fmt.Errorf("decompression limit exceeded: %s (ratio >%d:1)",
						f.Name, util.MaxDecompressRatio)
				}

				if _, err := dstFile.Write(buf[:n]); err != nil {
					_ = dstFile.Close()
					_ = fileInArchive.Close()
					_ = os.Remove(outPath)
					return fmt.Errorf("write %s: %w", outPath, err)
				}

				done += int64(n)
				if opts.Progress != nil {
					progress, speed, eta := util.Statify(done, totalSize, startTime)
					opts.Progress(progress, fmt.Sprintf("%d/%d", i+1, len(reader.File)))
					if opts.Status != nil {
						opts.Status(fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", speed, eta))
					}
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = dstFile.Close()
				_ = fileInArchive.Close()
				return fmt.Errorf("read %s: %w", f.Name, readErr)
			}
		}

		_ = dstFile.Close()
		_ = fileInArchive.Close()
	}

	return nil
}
