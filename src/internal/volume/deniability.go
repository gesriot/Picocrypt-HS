package volume

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/chacha20"
)

// newDeniabilityReader is identity in production; tests replace it to inject
// short reads and verify the io.ReadFull loops pin the rekey boundary to a
// fixed block count regardless of read chunking. Mirrors newPayloadReader in
// decrypt.go for the main payload path.
var newDeniabilityReader = func(r io.Reader) io.Reader { return r }

// isDeniableReadVersion reads IsDeniable's encoded version prefix. It is a
// package-level seam (mirroring newDeniabilityReader) so tests can inject an I/O
// failure on a file that already cleared the size guard, exercising the
// read-error branch that is otherwise unreachable on a real filesystem.
var isDeniableReadVersion = func(r io.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// AddDeniability wraps a volume with a deniability layer.
// This encrypts the entire volume with XChaCha20 using a separate key derived from the password.
//
// CRITICAL: Deniability uses its own Argon2 derivation (4 passes, 1 GiB, 4 threads)
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
	incompletePath := volumePath + ".incomplete"

	if err := os.Rename(volumePath, tmpPath); err != nil {
		return fmt.Errorf("rename to tmp: %w", err)
	}

	// Helper to restore original file on error
	restoreOriginal := func() {
		_ = os.Remove(incompletePath)
		_ = os.Rename(tmpPath, volumePath)
	}

	// #nosec G304 -- tmpPath is temp file created by this function
	fin, err := os.Open(tmpPath)
	if err != nil {
		restoreOriginal()
		return fmt.Errorf("open tmp: %w", err)
	}
	defer func() { _ = fin.Close() }()

	fout, err := fileops.CreateSecureNoSymlink(incompletePath)
	if err != nil {
		_ = fin.Close()
		restoreOriginal()
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = fout.Close() }()

	// Generate random salt and nonce
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		restoreOriginal()
		return err
	}
	nonce, err := crypto.RandomBytes(24)
	if err != nil {
		restoreOriginal()
		return err
	}

	// Write salt and nonce to output
	if _, err := fout.Write(salt); err != nil {
		restoreOriginal()
		return fmt.Errorf("write salt: %w", err)
	}
	if _, err := fout.Write(nonce); err != nil {
		restoreOriginal()
		return fmt.Errorf("write nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters)
	key := deriveDeniabilityKey([]byte(password), salt)
	defer crypto.SecureZero(key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		restoreOriginal()
		return fmt.Errorf("create cipher: %w", err)
	}

	// Encrypt the entire volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	reader := newDeniabilityReader(io.Reader(fin))
	startTime := time.Now()

	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				restoreOriginal()
				return fmt.Errorf("write encrypted: %w", err)
			}

			done += int64(n)
			// Pin the rekey boundary to a fixed block count regardless of read
			// chunking: io.ReadFull delivers full MiB blocks, so the counter
			// advances by util.MiB per block. The threshold is a MiB multiple
			// and only crossable on a full block, so the final partial block's
			// over-count is irrelevant (the loop breaks at EOF).
			counter += int64(util.MiB)

			if reporter != nil {
				progress, speed, eta := util.Statify(done, total, startTime)
				reporter.SetProgress(progress, "")
				reporter.SetStatus(fmt.Sprintf("Adding deniability at %.2f MiB/s (ETA: %s)", speed, eta))
				reporter.Update()
			}

			// Rekey after 60 GiB (deniability uses SHA3-256(nonce) for rekeying)
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					restoreOriginal()
					return fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			restoreOriginal()
			return fmt.Errorf("read: %w", readErr)
		}
	}

	_ = fin.Close()

	// Sync to ensure all data is written before renaming
	if err := fout.Sync(); err != nil {
		restoreOriginal()
		return fmt.Errorf("sync output: %w", err)
	}
	_ = fout.Close()

	// Clean up: remove the .tmp (holds inner .pcv ciphertext) and rename
	// .incomplete to final name.
	// NOTE: this site is intentionally error-checked (not `_ =`): a failed .tmp
	// removal must abort before the rename so both files are left for manual
	// recovery. Preserve that control flow.
	if err := os.Remove(tmpPath); err != nil {
		// .tmp removal failed, but we have the complete .incomplete
		// Don't try to rename - leave both files for manual inspection
		// User can manually: verify .incomplete is correct, remove .tmp, rename .incomplete
		return fmt.Errorf("remove tmp failed (data saved in %s): %w", incompletePath, err)
	}

	if err := os.Rename(incompletePath, volumePath); err != nil {
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
// CRITICAL: Must read salt(16) + nonce(24) from the beginning,
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

	// #nosec G304 -- volumePath is user-provided .pcv file
	fin, err := os.Open(volumePath)
	if err != nil {
		return "", fmt.Errorf("open volume: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Determine output path (strip .tmp suffixes, add .tmp)
	outputPath := volumePath
	for strings.HasSuffix(outputPath, ".tmp") {
		outputPath = strings.TrimSuffix(outputPath, ".tmp")
	}
	outputPath += ".tmp"

	fout, err := fileops.CreateSecureNoSymlink(outputPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}

	// Helper to cleanup on error
	cleanup := func() {
		_ = fout.Close()
		_ = os.Remove(outputPath)
	}

	// Read salt and nonce
	salt := make([]byte, 16)
	nonce := make([]byte, 24)

	if _, err := io.ReadFull(fin, salt); err != nil {
		cleanup()
		return "", fmt.Errorf("read salt: %w", err)
	}
	if _, err := io.ReadFull(fin, nonce); err != nil {
		cleanup()
		return "", fmt.Errorf("read nonce: %w", err)
	}

	// Derive key using Argon2 (normal mode parameters)
	key := deriveDeniabilityKey([]byte(password), salt)
	defer crypto.SecureZero(key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("create cipher: %w", err)
	}

	// Decrypt the volume
	var done int64
	var counter int64
	buf := util.GetMiBBuffer()
	defer util.PutMiBBuffer(buf)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	reader := newDeniabilityReader(io.Reader(fin))
	startTime := time.Now()

	for {
		n, readErr := io.ReadFull(reader, buf)
		if n > 0 {
			cipher.XORKeyStream(dst[:n], buf[:n])

			if _, err := fout.Write(dst[:n]); err != nil {
				cleanup()
				return "", fmt.Errorf("write decrypted: %w", err)
			}

			done += int64(n)
			// Pin the rekey boundary to a fixed block count (see AddDeniability):
			// io.ReadFull delivers full MiB blocks, so the rekey offset is
			// independent of how the underlying reader chunks its reads.
			counter += int64(util.MiB)

			if reporter != nil {
				progress, speed, eta := util.Statify(done, total, startTime)
				reporter.SetProgress(progress, "")
				reporter.SetStatus(fmt.Sprintf("Removing deniability at %.2f MiB/s (ETA: %s)", speed, eta))
				reporter.Update()
			}

			// Rekey after 60 GiB
			if counter >= crypto.RekeyThreshold {
				cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
				if err != nil {
					cleanup()
					return "", fmt.Errorf("rekey: %w", err)
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			cleanup()
			return "", fmt.Errorf("read: %w", readErr)
		}
	}

	_ = fin.Close()

	// Sync to ensure all data is written before verification
	if err := fout.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync output: %w", err)
	}
	_ = fout.Close()

	// Verify the decrypted file is a valid volume
	// #nosec G304 -- outputPath is derived from user-provided volumePath
	verifyFin, err := os.Open(outputPath)
	if err != nil {
		_ = os.Remove(outputPath)
		return "", fmt.Errorf("open for verification: %w", err)
	}

	versionEnc := make([]byte, 15)
	if _, err := io.ReadFull(verifyFin, versionEnc); err != nil {
		_ = verifyFin.Close()
		_ = os.Remove(outputPath)
		return "", fmt.Errorf("read version: %w", err)
	}
	_ = verifyFin.Close()

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		_ = os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	if !header.MatchVersion(versionDec) {
		_ = os.Remove(outputPath)
		return "", errors.New("password is incorrect or the file is not a volume")
	}

	return outputPath, nil
}

// IsDeniable checks if a volume appears to have deniability protection.
//
// The leading bytes of a deniable volume are random salt/nonce bytes, while a
// regular volume starts with an RS5-encoded version. A version decode failure is
// ambiguous: it can be a deniable wrapper or a damaged regular header. Resolve
// that ambiguity by checking whether the following comment-length and flags
// fields still look like a regular Picocrypt header.
func IsDeniable(volumePath string, rs *encoding.RSCodecs) bool {
	// #nosec G304 -- volumePath is user-provided .pcv file
	fin, err := os.Open(volumePath)
	if err != nil {
		return false
	}
	defer func() { _ = fin.Close() }()

	// QUAL-02 negative pre-guard: a deniability-wrapped volume always wraps a COMPLETE
	// inner regular volume, so its on-disk size is at least salt(16) + nonce(24) +
	// header.BaseHeaderSize. A file shorter than that cannot be deniable — it is a
	// truncated/corrupt regular volume (or junk). Classifying such a short file as
	// deniable mis-routes it down the deniability-strip path; reject it here instead.
	// This only ADDS a negative rejection; the positive RS5-magic detection path below
	// is format-frozen and unchanged.
	const minDeniableSize = 16 + 24 + header.BaseHeaderSize
	if fi, err := fin.Stat(); err != nil || fi.Size() < int64(minDeniableSize) {
		return false // too short to be a deniable volume (truncated/corrupt regular)
	}

	versionEnc := make([]byte, 15)
	if _, err := isDeniableReadVersion(fin, versionEnc); err != nil {
		// Size already cleared the minimum above, so a short read here means an I/O
		// error rather than truncation — treat as non-deniable (cannot confirm).
		return false
	}

	versionDec, err := encoding.Decode(rs.RS5, versionEnc, false)
	if err != nil {
		return !looksLikeRegularHeaderAfterDamagedVersion(fin, rs)
	}

	if header.MatchVersion(versionDec) {
		return false
	}

	return !looksLikeRegularHeaderAfterDamagedVersion(fin, rs)
}

func looksLikeRegularHeaderAfterDamagedVersion(fin *os.File, rs *encoding.RSCodecs) bool {
	commentLenEnc := make([]byte, header.CommentLenEncSize)
	if _, err := fin.ReadAt(commentLenEnc, int64(header.VersionEncSize)); err != nil {
		return false
	}
	commentLenDec, err := encoding.Decode(rs.RS5, commentLenEnc, false)
	if err != nil {
		return false
	}
	commentsLen, ok := parseHeaderCommentLen(commentLenDec)
	if !ok {
		return false
	}

	flagsOffset := int64(header.VersionEncSize + header.CommentLenEncSize + commentsLen*3)
	flagsEnc := make([]byte, header.FlagsEncSize)
	if _, err := fin.ReadAt(flagsEnc, flagsOffset); err != nil {
		return false
	}
	flagsDec, err := encoding.Decode(rs.RS5, flagsEnc, false)
	if err != nil {
		return false
	}
	return headerFlagsBytesPlausible(flagsDec)
}

func parseHeaderCommentLen(b []byte) (int, bool) {
	if len(b) != 5 {
		return 0, false
	}
	var n int
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > header.MaxCommentLen {
		return 0, false
	}
	return n, true
}

func headerFlagsBytesPlausible(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	for _, c := range b[:5] {
		if c != 0 && c != 1 {
			return false
		}
	}
	return true
}
