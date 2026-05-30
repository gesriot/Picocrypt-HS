package volume

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/log"
	"Picocrypt-NG/internal/util"
)

var unpackArchive = fileops.Unpack

// Decrypt performs a complete volume decryption operation.
// This is the main entry point for decryption.
// If ctx is nil, a background context is used.
func Decrypt(ctx context.Context, req *DecryptRequest) error {
	opCtx := NewDecryptContext(ctx, req)
	defer opCtx.Close() // Secure zeroing of key material

	log.Info("starting decryption", log.String("input", req.InputFile))

	// Phase 1: Preprocess (recombine if split, remove deniability)
	if err := decryptPreprocess(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req) // Clean up any partial temp files
		return err
	}

	// Phase 2: Read header
	if err := decryptReadHeader(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	// Phase 3: Derive keys
	if err := decryptDeriveKeys(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	// Phase 4: Process keyfiles
	if err := decryptProcessKeyfiles(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	// Phase 5: Verify authentication
	if err := decryptVerifyAuth(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	// Phase 5.5 (optional): Two-pass verification - verify MAC BEFORE decryption
	// This addresses security audit recommendation PCC-004: authenticate ciphertext
	// before decrypting. Slower but ensures we never decrypt attacker-controlled data.
	if req.VerifyFirst {
		if err := decryptVerifyMACFirst(opCtx, req); err != nil {
			cleanupDecrypt(opCtx, req)
			return err
		}

		// Re-derive keys to reset HKDF stream for actual decryption
		if err := decryptDeriveKeys(opCtx, req); err != nil {
			cleanupDecrypt(opCtx, req)
			return err
		}
		if err := decryptProcessKeyfiles(opCtx, req); err != nil {
			cleanupDecrypt(opCtx, req)
			return err
		}
		if err := decryptVerifyAuth(opCtx, req); err != nil {
			cleanupDecrypt(opCtx, req)
			return err
		}
	}

	// Phase 6: Decrypt payload
	if err := decryptPayload(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	// Phase 7: Finalize (verify MAC, cleanup, auto-unzip)
	if err := decryptFinalize(opCtx, req); err != nil {
		cleanupDecrypt(opCtx, req)
		return err
	}

	log.Info("decryption completed successfully")
	return nil
}

func decryptPreprocess(ctx *OperationContext, req *DecryptRequest) error {
	inputFile := req.InputFile

	// Recombine split chunks if needed
	if req.Recombine {
		ctx.SetStatus("Recombining chunks...")

		inputBase := inputFile
		if base, ok := fileops.SplitChunkBase(inputFile); ok {
			inputBase = base
		}

		outputPath := inputBase
		err := fileops.Recombine(fileops.RecombineOptions{
			InputBase:  inputBase,
			OutputPath: outputPath,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
			Cancel: func() bool {
				return ctx.IsCancelled()
			},
		})
		if err != nil {
			return err
		}

		// Store recombined file path for cleanup
		ctx.RecombinedFile = outputPath
		ctx.TempFile = outputPath
		inputFile = outputPath
	}

	// Remove deniability wrapper if present
	if req.Deniability {
		decrypted, err := RemoveDeniability(inputFile, req.Password, ctx.Reporter, req.RSCodecs)
		if err != nil {
			return err
		}

		// Note: if we recombined, the recombined file path is stored in ctx.RecombinedFile
		// for cleanup after decryption completes (see decryptFinalize)

		ctx.TempFile = decrypted
		inputFile = decrypted
	}

	ctx.InputFile = inputFile

	// Get file size
	stat, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	ctx.Total = stat.Size() - int64(header.BaseHeaderSize)

	return nil
}

func decryptReadHeader(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Reading values...")

	fin, err := os.Open(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	reader := header.NewReader(fin, req.RSCodecs)
	result, err := reader.ReadHeader()
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	ctx.Header = result.Header

	// Handle decode errors
	if result.DecodeError != nil {
		if req.ForceDecrypt {
			// Continue but mark as damaged
		} else {
			return fmt.Errorf("header damaged: %w", result.DecodeError)
		}
	}

	// Update total size with comment length
	ctx.Total -= int64(len(ctx.Header.Comments)) * 3

	// Check for legacy v1
	ctx.IsLegacyV1 = ctx.Header.IsLegacyV1()

	// Determine if keyfiles are needed based on header
	ctx.UseKeyfiles = ctx.Header.Flags.UseKeyfiles

	return nil
}

func decryptDeriveKeys(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Deriving key...")

	key, err := deriveVolumeKey([]byte(req.Password), ctx.Header.Salt, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}
	ctx.Key = key

	return nil
}

func decryptProcessKeyfiles(ctx *OperationContext, req *DecryptRequest) error {
	if !ctx.UseKeyfiles {
		ctx.KeyfileHash = make([]byte, 32)
		return nil
	}

	if len(req.Keyfiles) == 0 {
		return perrors.NewValidationError("keyfiles", "keyfiles required but none provided")
	}

	ctx.SetStatus("Reading keyfiles...")

	result, err := keyfile.Process(req.Keyfiles, ctx.Header.Flags.KeyfileOrdered, func(p float32) {
		ctx.UpdateProgress(p, "")
	})
	if err != nil {
		return err
	}

	ctx.KeyfileKey = result.Key
	ctx.KeyfileHash = result.Hash

	return nil
}

func decryptVerifyAuth(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Calculating values...")

	if ctx.IsLegacyV1 {
		// v1: HKDF initialized AFTER keyfile XOR
		// First verify password using SHA3-512(key)
		authResult := header.VerifyV1Header(ctx.Key, ctx.Header)

		if !authResult.Valid {
			if req.ForceDecrypt {
				// Continue anyway
			} else {
				return header.NewPasswordError()
			}
		}

		// Verify keyfiles
		if ctx.UseKeyfiles {
			if !header.VerifyKeyfileHash(ctx.KeyfileHash, ctx.Header.KeyfileHash) {
				if req.ForceDecrypt {
					// Continue anyway
				} else {
					return header.NewKeyfileError(ctx.Header.Flags.KeyfileOrdered)
				}
			}
		}

		// For v1, XOR keyfile key into main key BEFORE HKDF
		key := ctx.Key
		if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
			// DATA-02: a legacy v1 volume may have been authored with an
			// even-count duplicate keyfile set whose unordered XOR cancels to
			// all-zeros. Original Picocrypt did not block this, so the volume
			// is already decryptable (its effective key is just the password
			// key). We must NOT block here like the v2 path does (D-11) — we
			// only WARN, mirroring the encrypt-side detection (D-10/D-12). This
			// sits AFTER the v1 SHA3-512(key) password verifier above, so it
			// does not let a wrong-password/tampered volume through.
			if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey) {
				log.Warn("duplicate keyfiles detected (keys cancel out)")
				ctx.SetStatus("Warning: duplicate keyfiles detected (keys cancel out)…")
			}
			key = keyfile.XORWithKey(ctx.Key, ctx.KeyfileKey)
		}

		// Initialize HKDF with XORed key (v1 behavior)
		hkdfStream := crypto.NewHKDFStream(key, ctx.Header.HKDFSalt)
		ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)

		// Store the XORed key for cipher initialization
		ctx.Key = key
	} else {
		// v2: HKDF initialized BEFORE keyfile XOR
		hkdfStream := crypto.NewHKDFStream(ctx.Key, ctx.Header.HKDFSalt)
		ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)

		// Read header subkey for verification
		subkeyHeader, err := ctx.SubkeyReader.HeaderSubkey()
		if err != nil {
			return err
		}

		// Verify header MAC
		authResult := header.VerifyV2Header(subkeyHeader, ctx.Header, ctx.KeyfileHash)

		if !authResult.Valid {
			if req.ForceDecrypt {
				// Continue anyway
			} else {
				// Could be password or tampered header
				return header.NewV2PasswordOrTamperError()
			}
		}

		// Verify keyfiles separately for better error messages
		if ctx.UseKeyfiles {
			if !header.VerifyKeyfileHash(ctx.KeyfileHash, ctx.Header.KeyfileHash) {
				if req.ForceDecrypt {
					// Continue anyway
				} else {
					return header.NewKeyfileError(ctx.Header.Flags.KeyfileOrdered)
				}
			}
		}

		// For v2, XOR keyfile key AFTER HKDF init
		if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
			if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey) {
				return perrors.ErrDuplicateKeyfiles
			}
			ctx.Key = keyfile.XORWithKey(ctx.Key, ctx.KeyfileKey)
		}
	}

	return nil
}

// decryptVerifyMACFirst performs a verification-only pass to check MAC before decryption.
// This addresses security audit recommendation PCC-004: the ciphertext is authenticated
// BEFORE any decryption occurs, ensuring we never apply crypto to attacker-controlled data.
//
// Trade-off: This doubles the I/O time since we read the file twice.
// The MAC is computed over ciphertext, so we can verify without decrypting.
//
// It runs the fast RS decode first (matching the decrypt pass's first pass); on a
// MAC mismatch with Reed-Solomon enabled it retries once with full RS correction
// (DATA-01) via decryptVerifyMACFirstWithDecode.
func decryptVerifyMACFirst(ctx *OperationContext, req *DecryptRequest) error {
	return decryptVerifyMACFirstWithDecode(ctx, req, true)
}

// decryptVerifyMACFirstWithDecode is the verify-first pass body, parameterized by
// fastDecode (sibling shape to decryptPayloadWithFastDecode):
//   - fastDecode=true:  skip RS error correction (fast path, matches the decrypt
//     pass's first pass). This is what the single call site uses.
//   - fastDecode=false: full RS error correction — the DATA-01 one-shot retry,
//     entered only on a MAC mismatch when Reed-Solomon is enabled.
//
// DATA-01 / Pitfall 4 (LOCKED guard rule): the retry guard is LOCAL — the
// fastDecode recursion parameter. It MUST NOT touch or reuse ctx.TriedFullRSDecode,
// which is owned exclusively by decryptFinalize; reusing it would disable the
// decrypt-pass retry or risk infinite recursion. The fastDecode=false invocation
// never recurses again, so the retry is one-shot (T-03-05).
func decryptVerifyMACFirstWithDecode(ctx *OperationContext, req *DecryptRequest, fastDecode bool) error {
	ctx.SetStatus("Verifying integrity (pass 1 of 2)...")

	// Read remaining subkeys (same order as decryptPayload)
	macSubkey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(macSubkey)

	// Skip serpent key read to maintain HKDF stream position
	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC for verification
	mac, err := crypto.NewMAC(macSubkey, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}

	// Open input file
	fin, err := os.Open(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Skip past header
	headerSize := header.HeaderSize(len(ctx.Header.Comments))
	if _, err := fin.Seek(int64(headerSize), 0); err != nil {
		return fmt.Errorf("seek past header: %w", err)
	}

	// Verification loop - read ciphertext and update MAC without decrypting
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64

	reedsolo := ctx.Header.Flags.ReedSolomon
	padded := ctx.Header.Flags.Padded

	// Pre-allocate buffer outside loop to reduce GC pressure
	var srcBufSize int
	if reedsolo {
		srcBufSize = util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize
	} else {
		srcBufSize = util.MiB
	}
	src := make([]byte, srcBufSize)

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := fin.Read(src)
		if n > 0 {
			srcData := src[:n]
			var data []byte

			// Decode Reed-Solomon if enabled. fastDecode mirrors the decrypt pass:
			// true skips RS error correction (fast path); false (the DATA-01 retry)
			// applies full RS correction to repair correctable damage.
			if reedsolo {
				var decErr error
				data, decErr = decodeWithRSFast(srcData, req.RSCodecs, done+int64(n) >= ctx.Total, padded, req.ForceDecrypt, fastDecode)
				if decErr != nil && !req.ForceDecrypt {
					return decErr
				}
			} else {
				data = srcData
			}

			// Update MAC with ciphertext (no decryption!)
			mac.Write(data)

			if reedsolo {
				done += int64(util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize)
			} else {
				done += int64(n)
			}

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress/2, fmt.Sprintf("%.2f%% (verifying)", progress*50)) // Show 0-50% for pass 1
			ctx.SetStatus(fmt.Sprintf("Verifying at %.2f MiB/s (ETA: %s)", speed, eta))

			// No rekey handling here: the verify pass holds no cipher to rekey. It
			// MACs the identical ciphertext bytes with the identical keyed MAC
			// subkey as the decrypt pass, and Rekey() only reseeds the cipher
			// nonce/IV (never the MAC), so the verify MAC matches the decrypt-pass
			// MAC across the 60 GiB rekey boundary without any rekeying.
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Verify MAC
	computedMAC := mac.Sum(nil)
	if subtle.ConstantTimeCompare(computedMAC, ctx.Header.AuthTag) != 1 {
		if req.ForceDecrypt {
			// Continue anyway - user forced it
			ctx.SetStatus("MAC verification failed, continuing anyway...")
		} else if ctx.Header.Flags.ReedSolomon && fastDecode {
			// DATA-01: the fast verify pass skips RS error correction, so
			// correctable damage (<= 4 errors / 136-byte block) yields wrong
			// ciphertext -> MAC mismatch. Before rejecting, retry the verify pass
			// ONCE with full RS correction (fastDecode=false), mirroring
			// decryptFinalize's guarded retry. Only reject if the full-RS verify
			// ALSO fails — a genuinely forged MAC (damage beyond the RS budget)
			// still returns ErrAuthFailed (PCC-004 fail-closed; T-03-04).
			//
			// State reset before recursing: the verify pass consumed MACSubkey()
			// and SerpentKey() from ctx.SubkeyReader (one-shot reads), so re-derive
			// keys + rebuild the HKDF stream first — otherwise the recursive read
			// errors with "subkey already consumed". The verify pass writes no
			// output, so there is no .incomplete file to remove.
			ctx.SetStatus("Repairing (verifying)...")
			if err := decryptDeriveKeys(ctx, req); err != nil {
				return err
			}
			if err := decryptProcessKeyfiles(ctx, req); err != nil {
				return err
			}
			if err := decryptVerifyAuth(ctx, req); err != nil {
				return err
			}
			// One-shot: fastDecode=false never recurses again (T-03-05).
			return decryptVerifyMACFirstWithDecode(ctx, req, false)
		} else {
			return perrors.ErrAuthFailed
		}
	}

	ctx.SetStatus("Integrity verified, decrypting...")
	return nil
}

func decryptPayload(ctx *OperationContext, req *DecryptRequest) error {
	return decryptPayloadWithFastDecode(ctx, req, true) // First pass: fast decode (skip RS error correction)
}

// decryptPayloadWithFastDecode performs the actual decryption.
// When fastDecode is true, RS decoding just returns first 128 bytes (no error correction).
// This matches the original Picocrypt behavior for performance.
func decryptPayloadWithFastDecode(ctx *OperationContext, req *DecryptRequest, fastDecode bool) error {
	// Read remaining subkeys
	macSubkey, err := ctx.SubkeyReader.MACSubkey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(macSubkey)

	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, ctx.Header.Flags.Paranoid)
	if err != nil {
		return err
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		ctx.Key,
		ctx.Header.Nonce,
		serpentKey,
		ctx.Header.SerpentIV,
		mac,
		ctx.SubkeyReader.Reader(),
		ctx.Header.Flags.Paranoid,
	)
	if err != nil {
		return err
	}
	// RS-03: zero the previous suite's key material before replacing it on retry.
	// On the full-RS-decode retry this function runs a second time; without this
	// the prior XChaCha20/Serpent key + MAC state would linger until ctx.Close()
	// at the very end (mirror OperationContext.Close, context.go:266-269).
	if ctx.CipherSuite != nil {
		ctx.CipherSuite.Close()
	}
	ctx.CipherSuite = cipherSuite

	// Open files
	fin, err := os.Open(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = fin.Close() }()

	// Skip past header
	headerSize := header.HeaderSize(len(ctx.Header.Comments))
	if _, err := fin.Seek(int64(headerSize), 0); err != nil {
		return fmt.Errorf("seek past header: %w", err)
	}

	fout, err := fileops.CreateSecure(req.OutputFile + ".incomplete")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = fout.Close() }()

	// Decrypt loop
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64
	var counter int64

	reedsolo := ctx.Header.Flags.ReedSolomon
	padded := ctx.Header.Flags.Padded

	// Pre-allocate buffers outside loop to reduce GC pressure
	// RS-encoded buffer is larger: 1 MiB * 136/128 = ~1.0625 MiB
	var srcBufSize int
	if reedsolo {
		srcBufSize = util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize
	} else {
		srcBufSize = util.MiB
	}
	src := make([]byte, srcBufSize) // Variable size due to RS encoding
	dst := util.GetMiBBuffer()      // Decrypted data is always <= 1 MiB
	defer util.PutMiBBuffer(dst)

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := fin.Read(src)
		if n > 0 {
			srcData := src[:n]
			var data []byte

			// Decode Reed-Solomon if enabled
			if reedsolo {
				var decErr error
				data, decErr = decodeWithRSFast(srcData, req.RSCodecs, done+int64(n) >= ctx.Total, padded, req.ForceDecrypt, fastDecode)
				if decErr != nil && !req.ForceDecrypt {
					return decErr
				}
			} else {
				data = srcData
			}

			dstData := dst[:len(data)]

			// Decrypt: MAC -> XChaCha20 -> Serpent
			ctx.CipherSuite.Decrypt(dstData, data)

			if _, err := fout.Write(dstData); err != nil {
				return fmt.Errorf("write plaintext: %w", err)
			}

			if reedsolo {
				done += int64(util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize)
			} else {
				done += int64(n)
			}
			counter += int64(len(data))

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress, fmt.Sprintf("%.2f%%", progress*100))
			if fastDecode {
				ctx.SetStatus(fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", speed, eta))
			} else {
				ctx.SetStatus(fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta))
			}

			// Rekey every 60 GiB
			if counter >= crypto.RekeyThreshold {
				if err := ctx.CipherSuite.Rekey(); err != nil {
					return err
				}
				counter = 0
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Sync before verifying MAC to ensure all data is written
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}

	return nil
}

func decryptFinalize(ctx *OperationContext, req *DecryptRequest) error {
	ctx.SetStatus("Comparing values...")

	// Verify MAC
	computedMAC := ctx.CipherSuite.Sum()
	if subtle.ConstantTimeCompare(computedMAC, ctx.Header.AuthTag) != 1 {
		// MAC verification failed
		// If Reed-Solomon is enabled, retry with full RS error correction (fastDecode=false)
		reedsolo := ctx.Header.Flags.ReedSolomon
		if reedsolo && !ctx.TriedFullRSDecode {
			// RS-03: state reset invariant — the full-RS retry below re-runs the
			// decrypt pipeline from a clean state so a second pass cannot bleed
			// state into (or corrupt) the output. Every mutated piece of state is
			// reset before the retry decode:
			//   - ctx.Key:         re-derived by decryptDeriveKeys BEFORE any v1/v2
			//                      keyfile XOR, so the key is never double-XORed.
			//   - ctx.KeyfileKey/Hash: re-set by decryptProcessKeyfiles.
			//   - ctx.SubkeyReader (HKDF stream): rebuilt by decryptVerifyAuth.
			//   - ctx.CipherSuite: freshly built in decryptPayloadWithFastDecode;
			//                      the previous suite is now Close()'d (key zeroed)
			//                      before reassignment (see that function).
			//   - input offset:    fresh os.Open + Seek(headerSize) per call.
			//   - output:          the old .incomplete is removed and recreated
			//                      (truncated) per call.
			// The Argon2id re-derivation is intentionally KEPT (D-07); reducing
			// Argon2 passes is Out of Scope — correctness over perf in a paranoid
			// tool. Do NOT cache derived material or skip the re-derive.
			ctx.TriedFullRSDecode = true

			// Remove incomplete file
			_ = os.Remove(req.OutputFile + ".incomplete")

			// Re-derive keys (needed to reset HKDF stream)
			if err := decryptDeriveKeys(ctx, req); err != nil {
				return err
			}
			if err := decryptProcessKeyfiles(ctx, req); err != nil {
				return err
			}
			if err := decryptVerifyAuth(ctx, req); err != nil {
				return err
			}

			// Retry with full RS decode (fastDecode=false)
			if err := decryptPayloadWithFastDecode(ctx, req, false); err != nil {
				return err
			}

			// Verify MAC again
			return decryptFinalize(ctx, req)
		}

		if req.ForceDecrypt {
			// Continue but mark as kept
			ctx.Kept = true
			if req.Kept != nil {
				*req.Kept = true
			}
		} else {
			// Remove incomplete output
			_ = os.Remove(req.OutputFile + ".incomplete")
			return perrors.ErrCorruptData
		}
	}

	// Rename to final output
	if err := os.Rename(req.OutputFile+".incomplete", req.OutputFile); err != nil {
		return fmt.Errorf("rename output: %w", err)
	}

	// Cleanup temp files
	if ctx.TempFile != "" {
		_ = os.Remove(ctx.TempFile)
	}
	// Remove recombined file if different from temp file (deniability changes TempFile)
	if ctx.RecombinedFile != "" && ctx.RecombinedFile != ctx.TempFile {
		_ = os.Remove(ctx.RecombinedFile)
	}

	// Auto-unzip if requested and output looks like a zip archive.
	// CLI auto-generated output names may omit .zip, so we also check file signature.
	if req.AutoUnzip && (strings.HasSuffix(req.OutputFile, ".zip") || isZipArchive(req.OutputFile)) {
		zipPath := req.OutputFile
		renamedFrom := ""
		if !strings.HasSuffix(req.OutputFile, ".zip") {
			zipPath = req.OutputFile + ".zip"
			if err := os.Rename(req.OutputFile, zipPath); err != nil {
				return fmt.Errorf("prepare auto-unzip: %w", err)
			}
			renamedFrom = req.OutputFile
		}

		ctx.SetStatus("Unzipping...")
		err := unpackArchive(fileops.UnpackOptions{
			ZipPath:   zipPath,
			SameLevel: req.SameLevel,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
			Cancel: ctx.IsCancelled,
		})
		if err != nil {
			if renamedFrom != "" {
				_ = os.Rename(zipPath, renamedFrom)
			}
			return fmt.Errorf("unzip: %w", err)
		}

		// Remove the zip
		_ = os.Remove(zipPath)
	}

	return nil
}

func isZipArchive(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- path is derived from user-selected output file
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	sig := make([]byte, 4)
	if _, err := io.ReadFull(f, sig); err != nil {
		return false
	}

	if sig[0] != 'P' || sig[1] != 'K' {
		return false
	}

	// ZIP signatures:
	// 0x03 0x04 = local file header
	// 0x05 0x06 = empty archive end record
	// 0x07 0x08 = spanned/split archive
	return (sig[2] == 0x03 && sig[3] == 0x04) ||
		(sig[2] == 0x05 && sig[3] == 0x06) ||
		(sig[2] == 0x07 && sig[3] == 0x08)
}

func cleanupDecrypt(ctx *OperationContext, req *DecryptRequest) {
	if ctx.TempFile != "" {
		_ = os.Remove(ctx.TempFile)
	}
	// Remove recombined file if different from temp file
	if ctx.RecombinedFile != "" && ctx.RecombinedFile != ctx.TempFile {
		_ = os.Remove(ctx.RecombinedFile)
	}
	_ = os.Remove(req.OutputFile + ".incomplete")
	// Note: ctx.Close() is called via defer in Decrypt()
}

// decodeWithRSFast decodes Reed-Solomon encoded data with optional fast decode.
// When fastDecode is true, it skips RS error correction and just returns the data bytes.
// This matches the original Picocrypt behavior for performance.
func decodeWithRSFast(data []byte, rs *encoding.RSCodecs, isLast, padded, forceDecode, fastDecode bool) ([]byte, error) {
	// Pre-allocate once: each 136-byte encoded chunk yields <= 128 decoded bytes.
	// Mirrors the encode side (encrypt.go:498). Unpad only shrinks the last chunk.
	result := make([]byte, 0, len(data)/encoding.RS128EncodedSize*encoding.RS128DataSize)
	fullBlockEncodedSize := util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize

	// Full 1 MiB block
	if len(data) == fullBlockEncodedSize {
		for i := 0; i < fullBlockEncodedSize; i += encoding.RS128EncodedSize {
			decoded, err := encoding.Decode(rs.RS128, data[i:i+encoding.RS128EncodedSize], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i : i+encoding.RS128DataSize] // Use raw data
				} else {
					return nil, perrors.ErrCorruptData
				}
			}

			// Unpad last chunk if needed
			if isLast && i == fullBlockEncodedSize-encoding.RS128EncodedSize && padded {
				decoded = encoding.Unpad(decoded)
			}

			result = append(result, decoded...)
		}
	} else {
		// Partial block - must have at least one RS128 chunk
		if len(data) < encoding.RS128EncodedSize {
			if forceDecode {
				return data, nil // Return raw data for severely truncated input
			}
			return nil, perrors.ErrCorruptData
		}

		chunks := len(data)/encoding.RS128EncodedSize - 1
		for i := 0; i < chunks; i++ {
			decoded, err := encoding.Decode(rs.RS128, data[i*encoding.RS128EncodedSize:(i+1)*encoding.RS128EncodedSize], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i*encoding.RS128EncodedSize : i*encoding.RS128EncodedSize+encoding.RS128DataSize]
				} else {
					return nil, perrors.ErrCorruptData
				}
			}
			result = append(result, decoded...)
		}

		// Last chunk (always unpad)
		lastChunkStart := chunks * encoding.RS128EncodedSize
		lastChunkEnd := lastChunkStart + encoding.RS128EncodedSize
		if lastChunkEnd > len(data) {
			lastChunkEnd = len(data)
		}
		decoded, err := encoding.Decode(rs.RS128, data[lastChunkStart:lastChunkEnd], fastDecode)
		if err != nil {
			if forceDecode {
				// Safely extract what we can
				safeEnd := lastChunkStart + encoding.RS128DataSize
				if safeEnd > len(data) {
					safeEnd = len(data)
				}
				decoded = data[lastChunkStart:safeEnd]
			} else {
				return nil, perrors.ErrCorruptData
			}
		}
		result = append(result, encoding.Unpad(decoded)...)
	}

	return result, nil
}
