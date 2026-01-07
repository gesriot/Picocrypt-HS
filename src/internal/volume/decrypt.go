package volume

import (
	"crypto/subtle"
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
	"Picocrypt-NG/internal/keyfile"
	"Picocrypt-NG/internal/util"
)

// Decrypt performs a complete volume decryption operation.
// This is the main entry point for decryption.
func Decrypt(req *DecryptRequest) error {
	ctx := NewDecryptContext(req)
	defer ctx.Close() // Secure zeroing of key material

	// Phase 1: Preprocess (recombine if split, remove deniability)
	if err := decryptPreprocess(ctx, req); err != nil {
		return err
	}

	// Phase 2: Read header
	if err := decryptReadHeader(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	// Phase 3: Derive keys
	if err := decryptDeriveKeys(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	// Phase 4: Process keyfiles
	if err := decryptProcessKeyfiles(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	// Phase 5: Verify authentication
	if err := decryptVerifyAuth(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	// Phase 6: Decrypt payload
	if err := decryptPayload(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	// Phase 7: Finalize (verify MAC, cleanup, auto-unzip)
	if err := decryptFinalize(ctx, req); err != nil {
		cleanupDecrypt(ctx, req)
		return err
	}

	return nil
}

func decryptPreprocess(ctx *OperationContext, req *DecryptRequest) error {
	inputFile := req.InputFile

	// Recombine split chunks if needed
	if req.Recombine {
		ctx.SetStatus("Recombining chunks...")

		outputPath := strings.TrimSuffix(inputFile, ".pcv") + ".pcv"
		err := fileops.Recombine(fileops.RecombineOptions{
			InputBase:  inputFile,
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

		// If we recombined, the recombined file is intermediate
		if ctx.TempFile != "" && ctx.TempFile != decrypted {
			// Keep track of original temp file for cleanup
		}

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
	defer fin.Close()

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

	key, err := crypto.DeriveKey([]byte(req.Password), ctx.Header.Salt, ctx.Header.Flags.Paranoid)
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
		return errors.New("keyfiles required but none provided")
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
				return errors.New("duplicate keyfiles detected")
			}
			ctx.Key = keyfile.XORWithKey(ctx.Key, ctx.KeyfileKey)
		}
	}

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

	serpentKey, err := ctx.SubkeyReader.SerpentKey()
	if err != nil {
		return err
	}

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
	ctx.CipherSuite = cipherSuite

	// Open files
	fin, err := os.Open(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer fin.Close()

	// Skip past header
	headerSize := header.HeaderSize(len(ctx.Header.Comments))
	if _, err := fin.Seek(int64(headerSize), 0); err != nil {
		return fmt.Errorf("seek past header: %w", err)
	}

	fout, err := os.Create(req.OutputFile + ".incomplete")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer fout.Close()

	// Decrypt loop
	ctx.Reporter.SetCanCancel(true)
	startTime := time.Now()
	var done int64
	var counter int64

	reedsolo := ctx.Header.Flags.ReedSolomon
	padded := ctx.Header.Flags.Padded

	for {
		if ctx.IsCancelled() {
			return errors.New("operation cancelled")
		}

		// Read chunk (RS encoded size if Reed-Solomon enabled)
		var src []byte
		if reedsolo {
			src = make([]byte, util.MiB/128*136) // RS128: 128 -> 136
		} else {
			src = make([]byte, util.MiB)
		}

		n, readErr := fin.Read(src)
		if n > 0 {
			src = src[:n]
			var data []byte

			// Decode Reed-Solomon if enabled
			if reedsolo {
				var decErr error
				data, decErr = decodeWithRSFast(src, req.RSCodecs, done+int64(n) >= ctx.Total, padded, req.ForceDecrypt, fastDecode)
				if decErr != nil && !req.ForceDecrypt {
					return decErr
				}
			} else {
				data = src
			}

			dst := make([]byte, len(data))

			// Decrypt: MAC → XChaCha20 → Serpent
			ctx.CipherSuite.Decrypt(dst, data)

			if _, err := fout.Write(dst); err != nil {
				return fmt.Errorf("write plaintext: %w", err)
			}

			if reedsolo {
				done += int64(util.MiB / 128 * 136)
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
			ctx.TriedFullRSDecode = true

			// Remove incomplete file
			os.Remove(req.OutputFile + ".incomplete")

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
			os.Remove(req.OutputFile + ".incomplete")
			return errors.New("the input file is damaged or modified")
		}
	}

	// Rename to final output
	if err := os.Rename(req.OutputFile+".incomplete", req.OutputFile); err != nil {
		return fmt.Errorf("rename output: %w", err)
	}

	// Cleanup temp files
	if ctx.TempFile != "" {
		os.Remove(ctx.TempFile)
	}
	// Remove recombined file if different from temp file (deniability changes TempFile)
	if ctx.RecombinedFile != "" && ctx.RecombinedFile != ctx.TempFile {
		os.Remove(ctx.RecombinedFile)
	}

	// Auto-unzip if requested and output is a .zip
	if req.AutoUnzip && strings.HasSuffix(req.OutputFile, ".zip") {
		ctx.SetStatus("Unzipping...")
		err := fileops.Unpack(fileops.UnpackOptions{
			ZipPath:   req.OutputFile,
			SameLevel: req.SameLevel,
			Progress: func(p float32, info string) {
				ctx.UpdateProgress(p, info)
			},
			Status: func(s string) {
				ctx.SetStatus(s)
			},
		})
		if err != nil {
			return fmt.Errorf("unzip: %w", err)
		}

		// Remove the zip
		os.Remove(req.OutputFile)
	}

	return nil
}

func cleanupDecrypt(ctx *OperationContext, req *DecryptRequest) {
	if ctx.TempFile != "" {
		os.Remove(ctx.TempFile)
	}
	// Remove recombined file if different from temp file
	if ctx.RecombinedFile != "" && ctx.RecombinedFile != ctx.TempFile {
		os.Remove(ctx.RecombinedFile)
	}
	os.Remove(req.OutputFile + ".incomplete")
	// Note: ctx.Close() is called via defer in Decrypt()
}

// decodeWithRSFast decodes Reed-Solomon encoded data with optional fast decode.
// When fastDecode is true, it skips RS error correction and just returns the data bytes.
// This matches the original Picocrypt behavior for performance.
func decodeWithRSFast(data []byte, rs *encoding.RSCodecs, isLast, padded, forceDecode, fastDecode bool) ([]byte, error) {
	var result []byte

	// Full 1 MiB block
	if len(data) == util.MiB/128*136 {
		for i := 0; i < util.MiB/128*136; i += 136 {
			decoded, err := encoding.Decode(rs.RS128, data[i:i+136], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i : i+128] // Use raw data
				} else {
					return nil, errors.New("the input file is irrecoverably damaged")
				}
			}

			// Unpad last chunk if needed
			if isLast && i == util.MiB/128*136-136 && padded {
				decoded = encoding.Unpad(decoded)
			}

			result = append(result, decoded...)
		}
	} else {
		// Partial block - must have at least one RS128 chunk (136 bytes)
		if len(data) < 136 {
			if forceDecode {
				return data, nil // Return raw data for severely truncated input
			}
			return nil, errors.New("the input file is truncated or severely damaged")
		}

		chunks := len(data)/136 - 1
		for i := 0; i < chunks; i++ {
			decoded, err := encoding.Decode(rs.RS128, data[i*136:(i+1)*136], fastDecode)
			if err != nil {
				if forceDecode {
					decoded = data[i*136 : i*136+128]
				} else {
					return nil, errors.New("the input file is irrecoverably damaged")
				}
			}
			result = append(result, decoded...)
		}

		// Last chunk (always unpad)
		lastChunkStart := chunks * 136
		lastChunkEnd := lastChunkStart + 136
		if lastChunkEnd > len(data) {
			lastChunkEnd = len(data)
		}
		decoded, err := encoding.Decode(rs.RS128, data[lastChunkStart:lastChunkEnd], fastDecode)
		if err != nil {
			if forceDecode {
				// Safely extract what we can
				safeEnd := lastChunkStart + 128
				if safeEnd > len(data) {
					safeEnd = len(data)
				}
				decoded = data[lastChunkStart:safeEnd]
			} else {
				return nil, errors.New("the input file is irrecoverably damaged")
			}
		}
		result = append(result, encoding.Unpad(decoded)...)
	}

	return result, nil
}
