// Package fileops provides file operations for Picocrypt volumes:
// zip archive creation, file splitting, chunk recombining, and zip extraction.
//
// These operations are used during encryption (zipping multiple files, splitting output)
// and decryption (recombining chunks, extracting zips).
package fileops

import (
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

func shouldDeleteSplitArtifact(basePath, candidate string) bool {
	prefix := basePath + "."
	if !strings.HasPrefix(candidate, prefix) {
		return false
	}

	suffix := strings.TrimPrefix(candidate, prefix)
	suffix = strings.TrimSuffix(suffix, ".incomplete")
	if suffix == "" {
		return false
	}

	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// SplitUnit represents the unit of measurement for chunk sizes when splitting files.
type SplitUnit int

const (
	SplitUnitKiB   SplitUnit = iota // Kibibytes (1024 bytes)
	SplitUnitMiB                    // Mebibytes (1024^2 bytes)
	SplitUnitGiB                    // Gibibytes (1024^3 bytes)
	SplitUnitTiB                    // Tebibytes (1024^4 bytes)
	SplitUnitTotal                  // Special: divide file into N equal parts
)

// SplitOptions configures how a file should be split into chunks.
type SplitOptions struct {
	InputPath string       // Path to file to split
	ChunkSize int          // Size of each chunk in Unit (or number of parts if Unit=Total)
	Unit      SplitUnit    // Unit of ChunkSize
	Progress  ProgressFunc // Progress callback (optional)
	Status    StatusFunc   // Status message callback (optional)
	Cancel    CancelFunc   // Cancellation check callback (optional)
}

// ChunkSizeToBytes converts a chunk size expressed in unit to a byte count,
// rejecting values that overflow int64. It is defined for the fixed-size units
// (KiB/MiB/GiB/TiB); SplitUnitTotal and any unknown unit are size-relative and
// returned unscaled (they cannot overflow here). Callers must reject the error:
// an unchecked overflow wraps negative, making Split a silent no-op.
func ChunkSizeToBytes(chunkSize int, unit SplitUnit) (int64, error) {
	size := int64(chunkSize)
	var unitBytes int64
	switch unit {
	case SplitUnitKiB:
		unitBytes = util.KiB
	case SplitUnitMiB:
		unitBytes = util.MiB
	case SplitUnitGiB:
		unitBytes = util.GiB
	case SplitUnitTiB:
		unitBytes = util.TiB
	default:
		return size, nil
	}
	if size > math.MaxInt64/unitBytes {
		return 0, fmt.Errorf("chunk size too large: %d would overflow when converted to bytes", chunkSize)
	}
	return size * unitBytes, nil
}

// Split divides a file into multiple sequential chunks for easier storage/transfer.
//
// Output files are named with numeric suffixes: inputPath.0, inputPath.1, inputPath.2, etc.
// Existing chunks with matching names are deleted before splitting begins.
//
// Use cases:
//   - Storing large encrypted volumes on FAT32 (4 GiB file size limit)
//   - Uploading to cloud services with file size restrictions
//   - Splitting for distribution across multiple storage media
//
// To reassemble, use Recombine() or concatenate files in order: cat file.pcv.* > file.pcv
func Split(opts SplitOptions) ([]string, error) {
	if opts.ChunkSize <= 0 {
		return nil, errors.New("chunk size must be greater than zero")
	}

	stat, err := os.Stat(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	totalSize := stat.Size()

	// Calculate actual chunk size in bytes
	var chunkSize int64
	if opts.Unit == SplitUnitTotal {
		// Divide into N equal parts
		chunkSize = int64(math.Ceil(float64(totalSize) / float64(opts.ChunkSize)))
	} else {
		chunkSize, err = ChunkSizeToBytes(opts.ChunkSize, opts.Unit)
		if err != nil {
			return nil, err
		}
	}

	numChunks := int(math.Ceil(float64(totalSize) / float64(chunkSize)))

	fin, err := os.Open(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Delete existing chunks first
	existingChunks, _ := filepath.Glob(opts.InputPath + ".*")
	for _, chunk := range existingChunks {
		if shouldDeleteSplitArtifact(opts.InputPath, chunk) {
			_ = os.Remove(chunk)
		}
	}

	var chunks []string
	var totalDone int64
	startTime := time.Now()

	for i := range numChunks {
		if opts.Cancel != nil && opts.Cancel() {
			// Clean up partial chunks
			for _, chunk := range chunks {
				_ = os.Remove(chunk)
			}
			return nil, errors.New("operation cancelled")
		}

		chunkPath := fmt.Sprintf("%s.%d.incomplete", opts.InputPath, i)
		fout, err := CreateSecureNoSymlink(chunkPath)
		if err != nil {
			// Clean up partial chunks
			for _, chunk := range chunks {
				_ = os.Remove(chunk)
			}
			return nil, fmt.Errorf("create chunk %d: %w", i, err)
		}

		var chunkDone int64
		buf := make([]byte, util.MiB)

		for chunkDone < chunkSize {
			if opts.Cancel != nil && opts.Cancel() {
				_ = fout.Close()
				_ = os.Remove(chunkPath)
				for _, chunk := range chunks {
					_ = os.Remove(chunk)
				}
				return nil, errors.New("operation cancelled")
			}

			// Adjust buffer size if near end of chunk
			remaining := chunkSize - chunkDone
			if remaining < int64(len(buf)) {
				buf = make([]byte, remaining)
			}

			n, readErr := fin.Read(buf)
			if n > 0 {
				if _, err := fout.Write(buf[:n]); err != nil {
					_ = fout.Close()
					_ = os.Remove(chunkPath)
					for _, chunk := range chunks {
						_ = os.Remove(chunk)
					}
					return nil, fmt.Errorf("write chunk %d: %w", i, err)
				}
				chunkDone += int64(n)
				totalDone += int64(n)

				if opts.Progress != nil {
					progress, speed, eta := util.Statify(totalDone, totalSize, startTime)
					opts.Progress(progress, fmt.Sprintf("%d/%d", i+1, numChunks))
					if opts.Status != nil {
						opts.Status(fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", speed, eta))
					}
				}
			}

			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = fout.Close()
				_ = os.Remove(chunkPath)
				for _, chunk := range chunks {
					_ = os.Remove(chunk)
				}
				return nil, fmt.Errorf("read for chunk %d: %w", i, readErr)
			}
		}

		// Sync to ensure data is flushed before renaming
		if err := fout.Sync(); err != nil {
			return nil, fmt.Errorf("sync chunk %d: %w", i, err)
		}

		if err := fout.Close(); err != nil {
			return nil, fmt.Errorf("close chunk %d: %w", i, err)
		}

		// Rename to final name
		finalPath := fmt.Sprintf("%s.%d", opts.InputPath, i)
		if err := os.Rename(chunkPath, finalPath); err != nil {
			return nil, fmt.Errorf("rename chunk %d: %w", i, err)
		}

		chunks = append(chunks, finalPath)
	}

	return chunks, nil
}
