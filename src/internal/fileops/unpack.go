package fileops

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/util"
)

// UnpackOptions configures archive extraction
type UnpackOptions struct {
	ZipPath        string // Path to .zip file
	ExtractDir     string // Directory to extract to (empty = same as zip, minus .zip)
	SameLevel      bool   // Extract to same directory as zip (not a subdirectory)
	Progress       ProgressFunc
	Status         StatusFunc
	Cancel         CancelFunc                  // Cancellation check callback (optional)
	AvailableSpace func(string) (int64, error) // Override free-space probe (optional, mainly for tests)
}

// normalizeZipPath normalizes a path from a zip file by converting all separators
// to the platform-appropriate separator. This handles cross-platform zip files.
func normalizeZipPath(zipPath string) string {
	// Replace all backslashes with forward slashes first
	normalized := strings.ReplaceAll(zipPath, "\\", "/")
	// Then convert to platform-specific separators
	return filepath.FromSlash(normalized)
}

// hasUnsafeWindowsTrimTraversalComponent rejects path segments that Windows can
// canonicalize into "." or ".." by trimming trailing spaces or periods.
func hasUnsafeWindowsTrimTraversalComponent(path string) bool {
	return slices.ContainsFunc(strings.Split(strings.ReplaceAll(path, "\\", "/"), "/"), becomesDotTraversalAfterWindowsTrim)
}

func becomesDotTraversalAfterWindowsTrim(segment string) bool {
	current := segment
	for {
		if current == "." || current == ".." {
			return true
		}
		if current == "" {
			return false
		}

		last := current[len(current)-1]
		if last != ' ' && last != '.' {
			return false
		}
		current = current[:len(current)-1]
	}
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
			// SEC-03 invariant (pinned by TestUnpackSymlinkEscape): every path
			// component is Lstat'd and any symlink rejected before a write, so a
			// symlinked intermediate dir cannot be followed out of the extraction
			// root. In-archive symlink entries never reach here as symlinks — they
			// are materialized as regular files (target string = body).
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

func pathWalkStart(path string) (string, []string) {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)

	start := volume
	if strings.HasPrefix(rest, string(filepath.Separator)) {
		start += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	if start == "" {
		start = "."
	}
	if rest == "" || rest == "." {
		return start, nil
	}

	return start, strings.Split(rest, string(filepath.Separator))
}

func walkExtractionRoot(current string, parts []string, create bool, allowLeadingSymlink bool) (string, error) {
	for i, part := range parts {
		next := filepath.Join(current, part)
		isLast := i == len(parts)-1

		info, err := os.Lstat(next)
		switch {
		case os.IsNotExist(err):
			if !create {
				return "", fmt.Errorf("extraction directory does not exist: %s", filepath.Join(current, filepath.Join(parts[i:]...)))
			}
			if err := os.Mkdir(next, 0700); err != nil {
				return "", fmt.Errorf("create extraction directory %s: %w", next, err)
			}
		case err != nil:
			return "", fmt.Errorf("stat extraction directory %s: %w", next, err)
		case info.Mode()&os.ModeSymlink != 0:
			if !allowLeadingSymlink || i != 0 {
				return "", fmt.Errorf("cannot extract to %s: path contains symlink %s", filepath.Join(current, filepath.Join(parts[i:]...)), next)
			}

			resolved, err := filepath.EvalSymlinks(next)
			if err != nil {
				return "", fmt.Errorf("resolve symlinked extraction directory %s: %w", next, err)
			}

			resolvedInfo, err := os.Stat(resolved)
			if err != nil {
				return "", fmt.Errorf("stat resolved extraction directory %s: %w", resolved, err)
			}
			if !resolvedInfo.IsDir() {
				return "", fmt.Errorf("cannot extract to %s: path resolves to a non-directory: %s", resolved, next)
			}

			current = resolved
			continue
		case !info.IsDir() && isLast:
			return "", fmt.Errorf("cannot extract to %s: path exists as a file (not a directory). Enable 'Same level' option or move/rename the existing file", filepath.Join(current, filepath.Join(parts[i:]...)))
		case !info.IsDir():
			return "", fmt.Errorf("cannot extract to %s: parent path is not a directory: %s", filepath.Join(current, filepath.Join(parts[i:]...)), next)
		}

		current = next
	}

	return current, nil
}

func allowLeadingExtractionRootSymlink(absDir, tempDir string) bool {
	cleanPath := filepath.Clean(absDir)
	cleanTemp := filepath.Clean(tempDir)
	if cleanTemp == "" {
		return false
	}
	if cleanPath == cleanTemp {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanTemp+string(filepath.Separator))
}

func prepareExtractionRoot(extractDir string, create bool) (string, error) {
	absDir, err := filepath.Abs(extractDir)
	if err != nil {
		return "", fmt.Errorf("resolve extraction directory %s: %w", extractDir, err)
	}

	current, parts := pathWalkStart(absDir)
	resolved, err := walkExtractionRoot(current, parts, create, allowLeadingExtractionRootSymlink(absDir, os.TempDir()))
	if err != nil {
		return "", err
	}

	return resolved, nil
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

	extractDir, err = prepareExtractionRoot(extractDir, !opts.SameLevel)
	if err != nil {
		return err
	}
	extractRoot, err := os.OpenRoot(extractDir)
	if err != nil {
		return fmt.Errorf("open extraction root %s: %w", extractDir, err)
	}
	defer func() {
		if err := extractRoot.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close extraction root: %w", err)
		}
	}()

	// First pass: create all directories and calculate the maximum write size
	// per output path for the free-space preflight.
	desiredSizes := make(map[string]int64)
	for _, f := range reader.File {
		// Normalize and validate path to prevent zip slip attacks
		if hasUnsafeWindowsTrimTraversalComponent(f.Name) {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := normalizeZipPath(f.Name)
		outPath, err := prepareExtractionPath(extractDir, normalizedName, f.FileInfo().IsDir())
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			continue
		}
		size, ok := util.SafeUint64ToInt64(f.UncompressedSize64)
		if !ok {
			return fmt.Errorf("file %s: uncompressed size exceeds int64 max", f.Name)
		}
		if size > desiredSizes[outPath] {
			desiredSizes[outPath] = size
		}
	}

	requiredAdditionalBytes, err := requiredAdditionalBytesForExtraction(desiredSizes)
	if err != nil {
		return err
	}
	probe := opts.AvailableSpace
	if probe == nil {
		probe = diskspace.Available
	}
	if available, err := probe(extractDir); err == nil && requiredAdditionalBytes > available {
		return fmt.Errorf("insufficient disk space for extraction: need %d bytes, have %d", requiredAdditionalBytes, available)
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

		// Revalidate immediately before writing. The first pass creates
		// directories and sizes the extraction; this pass closes the parent-dir
		// swap window and writes through os.Root so the open is root-confined.
		if hasUnsafeWindowsTrimTraversalComponent(f.Name) {
			return errors.New("potentially malicious zip item path")
		}
		normalizedName := normalizeZipPath(f.Name)
		outPath, err := prepareExtractionPath(extractDir, normalizedName, false)
		if err != nil {
			return err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", f.Name, err)
		}

		dstFile, err := extractRoot.OpenFile(normalizedName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			_ = fileInArchive.Close()
			return fmt.Errorf("create %s: %w", outPath, err)
		}
		removeExtractedFile := func() {
			_ = extractRoot.Remove(normalizedName)
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
				removeExtractedFile()
				return errors.New("operation cancelled")
			}

			n, readErr := fileInArchive.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > maxBytes {
					_ = dstFile.Close()
					_ = fileInArchive.Close()
					removeExtractedFile()
					return fmt.Errorf("decompression limit exceeded: %s (ratio >%d:1)",
						f.Name, util.MaxDecompressRatio)
				}

				if _, err := dstFile.Write(buf[:n]); err != nil {
					_ = dstFile.Close()
					_ = fileInArchive.Close()
					removeExtractedFile()
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
