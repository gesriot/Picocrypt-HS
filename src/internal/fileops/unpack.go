package fileops

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
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
}

// Unpack extracts a zip archive to the specified directory.
func Unpack(opts UnpackOptions) error {
	reader, err := zip.OpenReader(opts.ZipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	// Calculate total uncompressed size
	var totalSize int64
	for _, f := range reader.File {
		totalSize += int64(f.UncompressedSize64)
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

	// First pass: create all directories
	for _, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}

		if f.FileInfo().IsDir() {
			outPath := filepath.Join(extractDir, f.Name)
			if err := os.MkdirAll(outPath, 0700); err != nil {
				return fmt.Errorf("create directory %s: %w", outPath, err)
			}
		}
	}

	// Second pass: extract files
	var done int64
	startTime := time.Now()

	for i, f := range reader.File {
		if strings.Contains(f.Name, "..") {
			return errors.New("potentially malicious zip item path")
		}

		if f.FileInfo().IsDir() {
			continue
		}

		outPath := filepath.Join(extractDir, f.Name)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
			return fmt.Errorf("create parent dir for %s: %w", outPath, err)
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in archive: %w", f.Name, err)
		}

		dstFile, err := os.Create(outPath)
		if err != nil {
			fileInArchive.Close()
			return fmt.Errorf("create %s: %w", outPath, err)
		}

		buf := make([]byte, util.MiB)
		for {
			n, readErr := fileInArchive.Read(buf)
			if n > 0 {
				if _, err := dstFile.Write(buf[:n]); err != nil {
					dstFile.Close()
					fileInArchive.Close()
					os.Remove(outPath)
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
				dstFile.Close()
				fileInArchive.Close()
				return fmt.Errorf("read %s: %w", f.Name, readErr)
			}
		}

		dstFile.Close()
		fileInArchive.Close()
	}

	return nil
}
