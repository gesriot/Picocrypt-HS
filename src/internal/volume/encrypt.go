package volume

import (
	"context"
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

// Encrypt performs a complete volume encryption operation.
// This is the main entry point for encryption.
// If ctx is nil, a background context is used.
func Encrypt(ctx context.Context, req *EncryptRequest) error {
	// Reject an unusable split chunk size before any preprocessing or key
	// derivation, so an overflowing size fails fast here instead of at the final
	// split step — where the silent no-op would delete the just-written volume.
	if err := req.validateSplit(); err != nil {
		return err
	}

	opCtx := NewEncryptContext(ctx, req)
	defer opCtx.Close() // Secure zeroing of key material

	log.Info("starting encryption", log.String("output", req.OutputFile))

	// Phase 1: Preprocess (zip if multiple files or compression requested)
	if err := encryptPreprocess(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req) // Clean up any partial temp files
		return err
	}

	// Phase 2: Generate cryptographic values
	if err := encryptGenerateValues(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 3: Write header
	if err := encryptWriteHeader(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 4: Derive keys
	if err := encryptDeriveKeys(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 5: Process keyfiles
	if err := encryptProcessKeyfiles(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 6: Compute header auth
	if err := encryptComputeAuth(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 7: Encrypt payload
	if err := encryptPayload(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	// Phase 8: Finalize (write auth values, add deniability, split)
	if err := encryptFinalize(opCtx, req); err != nil {
		cleanupEncrypt(opCtx, req)
		return err
	}

	log.Info("encryption completed successfully")
	return nil
}

func preprocessInputFiles(req *EncryptRequest) []string {
	if len(req.InputFiles) > 0 {
		return req.InputFiles
	}
	if req.InputFile != "" {
		return []string{req.InputFile}
	}
	return nil
}

func encryptPreprocess(ctx *OperationContext, req *EncryptRequest) error {
	inputFiles := preprocessInputFiles(req)

	// Create a zip when the selection is anything other than a single bare file:
	// multiple files, a single file with compression requested, or any folder
	// selection (even one containing a single file). A dropped folder is labelled
	// "Zip and Encrypt" by the UI and named "<name>.zip.pcv", so it must decrypt to
	// a real zip that preserves the folder structure — see issue #130. OnlyFolders
	// is the signal that a folder (not a bare file) was selected.
	if len(inputFiles) > 1 || (len(inputFiles) == 1 && (req.Compress || len(req.OnlyFolders) > 0)) {
		ctx.SetStatus("Compressing files...")

		// Create temp zip ciphers for encrypting the temporary file
		var err error
		ctx.TempCiphers, err = fileops.NewTempZipCiphers()
		if err != nil {
			return err
		}

		zipReq := *req
		zipReq.InputFiles = inputFiles

		commonRoot, entryNames, err := buildZipEntryNames(&zipReq)
		if err != nil {
			return err
		}

		// Create the zip
		ctx.TempFile = strings.TrimSuffix(req.OutputFile, ".pcv") + ".tmp"
		err = fileops.CreateZip(fileops.ZipOptions{
			Files:      inputFiles,
			RootDir:    commonRoot,
			EntryNames: entryNames,
			OutputPath: ctx.TempFile,
			Compress:   req.Compress,
			Cipher:     ctx.TempCiphers,
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

		ctx.InputFile = ctx.TempFile
		ctx.TempZipInUse = true
	} else if len(inputFiles) == 1 {
		ctx.InputFile = inputFiles[0]
	} else {
		ctx.InputFile = req.InputFile
	}

	return nil
}

func encryptGenerateValues(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Generating values...")

	// Generate random cryptographic values
	salt, err := crypto.RandomBytes(header.SaltSize)
	if err != nil {
		return err
	}

	hkdfSalt, err := crypto.RandomBytes(header.HKDFSaltSize)
	if err != nil {
		return err
	}

	serpentIV, err := crypto.RandomBytes(header.SerpentIVSize)
	if err != nil {
		return err
	}

	nonce, err := crypto.RandomBytes(header.NonceSize)
	if err != nil {
		return err
	}

	// Get input file size for padded flag
	stat, err := os.Stat(ctx.InputFile)
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	ctx.Total = stat.Size()

	// Determine if padding is needed (RS internals)
	// Padding is required when the last partial block would leave fewer than RS128DataSize
	// bytes after RS128 encoding chunks are filled.
	ctx.Padded = ctx.Total%int64(util.MiB) >= int64(util.MiB)-encoding.RS128DataSize

	// Create header
	ctx.Header = header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	ctx.Header.Comments = req.Comments
	ctx.Header.Flags = header.Flags{
		Paranoid:       req.Paranoid,
		UseKeyfiles:    len(req.Keyfiles) > 0,
		KeyfileOrdered: req.KeyfileOrdered,
		ReedSolomon:    req.ReedSolomon,
		Padded:         ctx.Padded,
	}

	return nil
}

func encryptWriteHeader(ctx *OperationContext, req *EncryptRequest) error {
	// Create output file
	fout, err := fileops.CreateSecureNoSymlink(req.OutputFile + ".incomplete")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}

	// Write header
	w := header.NewWriter(fout, req.RSCodecs)
	if _, err := w.WriteHeader(ctx.Header); err != nil {
		_ = fout.Close()
		_ = os.Remove(fout.Name())
		return fmt.Errorf("write header: %w", err)
	}

	_ = fout.Close()
	return nil
}

func encryptDeriveKeys(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Deriving key...")

	key, err := deriveVolumeKey([]byte(req.Password), ctx.Header.Salt, req.Paranoid)
	if err != nil {
		return err
	}
	ctx.Key = key

	return nil
}

func encryptProcessKeyfiles(ctx *OperationContext, req *EncryptRequest) error {
	if len(req.Keyfiles) == 0 {
		ctx.KeyfileHash = make([]byte, 32)
		return nil
	}

	ctx.SetStatus("Reading keyfiles...")
	ctx.UseKeyfiles = true

	result, err := keyfile.Process(req.Keyfiles, req.KeyfileOrdered, func(p float32) {
		ctx.UpdateProgress(p, "")
	})
	if err != nil {
		return err
	}

	ctx.KeyfileKey = result.Key
	ctx.KeyfileHash = result.Hash

	return nil
}

func encryptComputeAuth(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Calculating values...")

	// v2: Initialize HKDF BEFORE keyfile XOR
	hkdfStream := crypto.NewHKDFStream(ctx.Key, ctx.Header.HKDFSalt)
	ctx.SubkeyReader = crypto.NewSubkeyReader(hkdfStream)

	// Read header subkey for v2 MAC
	subkeyHeader, err := ctx.SubkeyReader.HeaderSubkey()
	if err != nil {
		return err
	}

	// Compute header MAC
	ctx.Header.KeyHash = header.ComputeV2HeaderMAC(subkeyHeader, ctx.Header, ctx.KeyfileHash)
	ctx.Header.KeyfileHash = ctx.KeyfileHash

	return nil
}

func encryptPayload(ctx *OperationContext, req *EncryptRequest) error {
	// Apply keyfile XOR to key (AFTER HKDF init for v2).
	if ctx.UseKeyfiles && ctx.KeyfileKey != nil {
		if keyfile.IsDuplicateKeyfileKey(ctx.KeyfileKey) {
			return perrors.ErrDuplicateKeyfiles
		}
		// SEC-05/WR-01: route the XOR reassignment through setKey for symmetry
		// with the decrypt path. keyfile.XORWithKey allocates a NEW slice, so the
		// old Argon2 backing array would otherwise linger until Close(); setKey
		// zeros it now. Safe here because HKDF has already extracted ctx.Key
		// (encryptComputeAuth read HeaderSubkey, so the stream's PRK is fixed) and
		// the cipher uses the XOR result, not the original key. The pointer-identity
		// guard means the no-keyfile path (this branch skipped) is never wiped.
		ctx.setKey(keyfile.XORWithKey(ctx.Key, ctx.KeyfileKey))
	}
	key := ctx.Key

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
	mac, err := crypto.NewMAC(macSubkey, req.Paranoid)
	if err != nil {
		return err
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		key,
		ctx.Header.Nonce,
		serpentKey,
		ctx.Header.SerpentIV,
		mac,
		ctx.SubkeyReader.Reader(),
		req.Paranoid,
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
	defer func() { _ = fin.Close() }()

	fout, err := fileops.OpenExistingNoSymlink(req.OutputFile+".incomplete", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer func() { _ = fout.Close() }()

	// Wrap with temp zip cipher if needed
	var reader io.Reader = fin
	if ctx.TempZipInUse && ctx.TempCiphers != nil {
		reader = fileops.WrapReaderWithCipher(fin, ctx.TempCiphers)
	}
	reader = newPayloadReader(reader)

	// Encrypt loop
	ctx.SetCanCancel(true)
	startTime := time.Now()
	var done int64
	var counter int64

	// Get buffers from pool to reduce GC pressure
	src := util.GetMiBBuffer()
	defer util.PutMiBBuffer(src)
	dst := util.GetMiBBuffer()
	defer util.PutMiBBuffer(dst)

	for {
		if ctx.IsCancelled() {
			return ctx.CancellationError()
		}

		n, readErr := io.ReadFull(reader, src)
		if n > 0 {
			srcData := src[:n]
			dstData := dst[:n]

			// Encrypt: Serpent -> XChaCha20 -> MAC
			ctx.CipherSuite.Encrypt(dstData, srcData)

			// Apply Reed-Solomon if enabled
			var writeData []byte
			if req.ReedSolomon {
				enc, err := encodeWithRS(dstData, req.RSCodecs)
				if err != nil {
					return fmt.Errorf("rs encode payload: %w", err)
				}
				writeData = enc
			} else {
				writeData = dstData
			}

			if _, err := fout.Write(writeData); err != nil {
				return fmt.Errorf("write ciphertext: %w", err)
			}

			done += int64(n)
			counter += int64(util.MiB)

			progress, speed, eta := util.Statify(done, ctx.Total, startTime)
			ctx.UpdateProgress(progress, fmt.Sprintf("%.2f%%", progress*100))
			ctx.SetStatus(fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", speed, eta))

			// Rekey every 60 GiB
			if counter >= crypto.RekeyThreshold {
				if err := ctx.CipherSuite.Rekey(); err != nil {
					return err
				}
				counter = 0
			}
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read input: %w", readErr)
		}
	}

	// Sync to ensure all encrypted data is written before finalize
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}

	return nil
}

func encryptFinalize(ctx *OperationContext, req *EncryptRequest) error {
	ctx.SetStatus("Writing values...")

	// Open output file for seeking
	fout, err := fileops.OpenExistingNoSymlink(req.OutputFile+".incomplete", os.O_RDWR)
	if err != nil {
		return fmt.Errorf("open output for auth: %w", err)
	}
	defer func() { _ = fout.Close() }()

	// Write auth values
	offset := header.AuthValuesOffset(len(ctx.Header.Comments))
	err = header.WriteAuthValues(
		fout,
		offset,
		ctx.Header.KeyHash,
		ctx.Header.KeyfileHash,
		ctx.CipherSuite.Sum(),
		req.RSCodecs,
	)
	if err != nil {
		return err
	}

	// Sync to ensure all data is written before rename
	if err := fout.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	_ = fout.Close()

	// Rename to final name
	if err := os.Rename(req.OutputFile+".incomplete", req.OutputFile); err != nil {
		return fmt.Errorf("rename output: %w", err)
	}

	// Add deniability if requested
	if req.Deniability {
		if err := AddDeniability(req.OutputFile, req.Password, ctx.Reporter); err != nil {
			return err
		}
	}

	// Split if requested
	if req.Split {
		ctx.SetStatus("Splitting...")
		_, err := fileops.Split(fileops.SplitOptions{
			InputPath: req.OutputFile,
			ChunkSize: req.ChunkSize,
			Unit:      req.ChunkUnit,
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

		// Remove the unsplit file
		_ = os.Remove(req.OutputFile)
	}

	// Clean up temp file
	if ctx.TempFile != "" {
		_ = os.Remove(ctx.TempFile)
	}

	return nil
}

func cleanupEncrypt(ctx *OperationContext, req *EncryptRequest) {
	if ctx.TempFile != "" {
		_ = os.Remove(ctx.TempFile)
	}
	_ = os.Remove(req.OutputFile + ".incomplete")
	// Note: ctx.Close() is called via defer in Encrypt()
}

// encodeWithRS encodes data with Reed-Solomon (rs128)
// For partial blocks (< 1 MiB), this ALWAYS adds a padding chunk, even if data
// is exactly divisible by 128, because the original Picocrypt always unpads
// the last chunk of partial blocks.
func encodeWithRS(data []byte, rs *encoding.RSCodecs) ([]byte, error) {
	// Pre-allocate result slice to avoid repeated reallocations
	// Each RS128DataSize-byte input chunk becomes RS128EncodedSize bytes (128 data + 8 parity)
	// For partial blocks, we add one more chunk for padding
	chunks := (len(data) + encoding.RS128DataSize - 1) / encoding.RS128DataSize
	if len(data) < util.MiB {
		chunks++ // Extra chunk for padding in partial blocks
	}
	result := make([]byte, 0, chunks*encoding.RS128EncodedSize)

	// encodeChunk RS-encodes one 128-byte input chunk directly into the tail of
	// the pre-sized result buffer, avoiding a per-chunk allocation and copy.
	// Output is byte-identical to encoding.Encode + append (golden-vector gated).
	encodeChunk := func(chunk []byte) error {
		start := len(result)
		result = result[:start+encoding.RS128EncodedSize]
		return encoding.EncodeInto(result[start:], rs.RS128, chunk)
	}

	// Full 1 MiB block - no padding needed within the block
	if len(data) == util.MiB {
		for i := 0; i < util.MiB; i += encoding.RS128DataSize {
			if err := encodeChunk(data[i : i+encoding.RS128DataSize]); err != nil {
				return nil, err
			}
		}
		return result, nil
	}

	// Partial block (< 1 MiB) - need to handle padding
	// Encode full 128-byte chunks
	fullChunks := len(data) / encoding.RS128DataSize
	for i := 0; i < fullChunks; i++ {
		if err := encodeChunk(data[i*encoding.RS128DataSize : (i+1)*encoding.RS128DataSize]); err != nil {
			return nil, err
		}
	}

	// ALWAYS add a padded chunk for partial blocks (matches original line 2071-2072)
	// This is because decryption always unpads the last chunk of partial blocks
	remaining := data[fullChunks*encoding.RS128DataSize:]
	if err := encodeChunk(encoding.Pad(remaining)); err != nil {
		return nil, err
	}

	return result, nil
}
