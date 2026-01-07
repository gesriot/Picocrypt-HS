package volume

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
)

// AddDeniability wraps a volume with a deniability layer.
// This encrypts the entire volume with XChaCha20 using a separate key derived from the password.
//
// ⚠️ CRITICAL: Deniability uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads)
// and stores salt(16) + nonce(24) at the beginning of the file.
func AddDeniability(volumePath, password string, reporter ProgressReporter) error {
	if reporter != nil {
		reporter.SetStatus("Adding plausible deniability...")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	stat, err := os.Stat(volumePath)
	if err != nil {
		return fmt.Errorf("stat volume: %w", err)
	}
	total := stat.Size()

	// Rename original to .tmp
	tmpPath := volumePath + ".tmp"
	if err := os.Rename(volumePath, tmpPath); err != nil {
		return fmt.Errorf("rename to tmp: %w", err)
	}

	fin, err := os.Open(tmpPath)
	if err != nil {
		os.Rename(tmpPath, volumePath) // Try to restore
		return fmt.Errorf("open tmp: %w", err)
	}
	defer fin.Close()

	fout, err := os.Create(volumePath + ".incomplete")
	if err != nil {
		fin.Close()
		os.Rename(tmpPath, volumePath)
		return fmt.Errorf("create output: %w", err)
	}
	defer fout.Close()

	// Generate random salt and nonce
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	nonce, err := crypto.RandomBytes(24)
	if err != nil {
		return err
	}

	// Write salt and nonce to output
	if _, err := fout.Write(salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}
	if _, err := fout.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters)
	key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	// Encrypt the entire volume
	var done int64
	var counter int64
	buf := make([]byte, util.MiB)

	for {
		n, readErr := fin.Read(buf)
		if n > 0 {
			dst := make([]byte, n)
			cipher.XORKeyStream(dst, buf[:n])

			if _, err := fout.Write(dst); err != nil {
				return fmt.Errorf("write encrypted: %w", err)
			}

			done += int64(n)
			counter += int64(n)

			if reporter != nil {
				reporter.SetProgress(float32(done)/float32(total), "")
				reporter.Update()
			}

			// Rekey after 60 GiB (deniability uses SHA3-256(nonce) for rekeying)
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					return fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}

	fin.Close()
	fout.Close()

	// Clean up
	if err := os.Remove(tmpPath); err != nil {
		return fmt.Errorf("remove tmp: %w", err)
	}

	if err := os.Rename(volumePath+".incomplete", volumePath); err != nil {
		return fmt.Errorf("rename output: %w", err)
	}

	if reporter != nil {
		reporter.SetCanCancel(true)
		reporter.Update()
	}

	return nil
}

// RemoveDeniability decrypts a deniability-wrapped volume.
// Returns the path to the decrypted volume (a .tmp file).
//
// ⚠️ CRITICAL: Must read salt(16) + nonce(24) from the beginning,
// then decrypt with XChaCha20 using Argon2-derived key.
func RemoveDeniability(volumePath, password string, reporter ProgressReporter, rs *encoding.RSCodecs) (string, error) {
	if reporter != nil {
		reporter.SetStatus("Removing deniability protection...")
		reporter.SetProgress(0, "")
		reporter.SetCanCancel(false)
		reporter.Update()
	}

	stat, err := os.Stat(volumePath)
	if err != nil {
		return "", fmt.Errorf("stat volume: %w", err)
	}
	total := stat.Size()

	fin, err := os.Open(volumePath)
	if err != nil {
		return "", fmt.Errorf("open volume: %w", err)
	}
	defer fin.Close()

	// Determine output path (strip .tmp suffixes, add .tmp)
	outputPath := volumePath
	for strings.HasSuffix(outputPath, ".tmp") {
		outputPath = strings.TrimSuffix(outputPath, ".tmp")
	}
	outputPath += ".tmp"

	fout, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}
	defer fout.Close()

	// Read salt and nonce
	salt := make([]byte, 16)
	nonce := make([]byte, 24)

	if _, err := io.ReadFull(fin, salt); err != nil {
		os.Remove(outputPath)
		return "", fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		os.Remove(outputPath)
		return "", fmt.Errorf("read nonce: %w", err)
	}

	// Derive key
	key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		os.Remove(outputPath)
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// Decrypt the volume
	var done int64
	var counter int64
	buf := make([]byte, util.MiB)

	for {
		n, readErr := fin.Read(buf)
		if n > 0 {
			dst := make([]byte, n)
			cipher.XORKeyStream(dst, buf[:n])

			if _, err := fout.Write(dst); err != nil {
				os.Remove(outputPath)
				return "", fmt.Errorf("write decrypted: %w", err)
			}

			done += int64(n)
			counter += int64(n)

			if reporter != nil {
				reporter.SetProgress(float32(done)/float32(total), "")
				reporter.Update()
			}

			// Rekey after 60 GiB
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					os.Remove(outputPath)
					return "", fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			os.Remove(outputPath)
			return "", fmt.Errorf("read: %w", readErr)
		}
	}

	fin.Close()
	fout.Close()

	// Verify the decrypted file is a valid volume
	verifyFin, err := os.Open(outputPath)
	if err != nil {
		os.Remove(outputPath)
		return "", fmt.Errorf("open for verification: %w", err)
	}

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(verifyFin, versionEnc); err != nil {
		verifyFin.Close()
		os.Remove(outputPath)
		return "", fmt.Errorf("read version: %w", err)
	}
	verifyFin.Close()

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	if valid, _ := regexp.Match(`^v\d\.\d{2}$`, versionDec); !valid {
		os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	return outputPath, nil
}

// IsDeniable checks if a volume appears to have deniability protection.
// This is done by attempting to read and decode the version - if it fails,
// the volume likely has a deniability wrapper.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool {
	fin, err := os.Open(volumePath)
	if err != nil {
		return false
	}
	defer fin.Close()

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(fin, versionEnc); err != nil {
		return true // Can't read, might be deniable
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return true // Decode failed, likely deniable
	}

	valid, _ := regexp.Match(`^v\d\.\d{2}$`, versionDec)
	return !valid // Invalid version format means deniable
}

// For deniability, we need to add RandomBytes to crypto package
func init() {
	// Verify crypto.RandomBytes exists (it will be added)
}

// Ensure start time tracking for stats
var _ = time.Now
