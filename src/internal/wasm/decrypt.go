// Package wasm provides memory-based encryption/decryption for WASM builds.
package wasm

import (
	"bytes"
	"crypto/subtle"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/keyfile"
	pwnorm "Picocrypt-NG/internal/password"
	"Picocrypt-NG/internal/util"
)

// Error codes matching website convention
const (
	ErrUnsupported       = 1 // Keyfiles required, deniability, split chunks
	ErrCorruptedHeader   = 2 // RS decode failure
	ErrWrongPassword     = 3 // Auth verification failed
	ErrModifiedData      = 4 // Payload MAC mismatch
	ErrRandomFailure     = 5 // Random generation failed (encrypt only)
	ErrKeyfilesRequired  = 7 // volume needs keyfiles, none provided
	ErrKeyfilesIncorrect = 8 // provided keyfiles don't match the stored hash
	ErrKeyfilesDuplicate = 9 // keyfiles XOR to an all-zero key
)

// DecryptResult is the successful output of DecryptVolume. On error the int
// code is non-zero and the result is the zero value.
type DecryptResult struct {
	Plaintext []byte
	Comments  string // plaintext header comments ("" if none)
}

// DecryptOptions configures an in-memory decryption.
type DecryptOptions struct {
	Keyfiles [][]byte // required iff the volume's header sets UseKeyfiles
}

// DecryptVolume decrypts a Picocrypt volume from memory.
// Returns (DecryptResult, 0) on success, or (zero, errorCode) on failure.
func DecryptVolume(volumeData, password []byte, opts DecryptOptions) (DecryptResult, int) {
	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Create reader from volume data
	reader := bytes.NewReader(volumeData)

	// Read header
	headerReader := header.NewReader(reader, rsCodecs)
	result, err := headerReader.ReadHeader()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}
	hdr := result.Header

	// Check for unsupported features
	if hasUnsupportedWASMFeature(hdr.Flags) {
		return DecryptResult{}, ErrUnsupported
	}

	// Keyfiles: required iff the header says so. Computed once (password-independent).
	keyfileHash := make([]byte, 32)
	defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileHash, keyfileHash)
	var keyfileKey []byte
	if hdr.Flags.UseKeyfiles {
		// v1-legacy keyfile volumes use a different key timing (HKDF AFTER the
		// keyfile XOR) that the WASM path does not implement; fail closed rather
		// than silently produce wrong plaintext. Rare combo → direct to desktop.
		if hdr.IsLegacyV1() {
			return DecryptResult{}, ErrUnsupported
		}
		if len(opts.Keyfiles) == 0 {
			return DecryptResult{}, ErrKeyfilesRequired
		}
		res, code := processWASMKeyfiles(opts.Keyfiles, hdr.Flags.KeyfileOrdered)
		if code != 0 {
			return DecryptResult{}, code
		}
		// Constant-time check against the stored hash before trying passwords,
		// so wrong keyfiles report distinctly from a wrong password.
		if !header.VerifyKeyfileHash(res.Hash, hdr.KeyfileHash) {
			crypto.SecureZero(res.Key)
			return DecryptResult{}, ErrKeyfilesIncorrect
		}
		keyfileKey = res.Key
		copy(keyfileHash, res.Hash)
		defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileKey, keyfileKey)
	}

	isLegacyV1 := hdr.IsLegacyV1()

	// Derive the key, trying each password normalization form (NFC/NFD/raw) until
	// one authenticates against the header (#19). ASCII passwords yield a single
	// candidate, so there is no extra KDF work for the common case.
	var key []byte
	var subkeyReader *crypto.SubkeyReader
	for _, cand := range pwnorm.Candidates(password) {
		k, err := crypto.DeriveKey(cand, hdr.Salt, hdr.Flags.Paranoid)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPasswordBytes, cand)
		if err != nil {
			return DecryptResult{}, ErrCorruptedHeader
		}
		valid, sr, errCode := verifyWASMHeader(k, hdr, keyfileHash, isLegacyV1)
		if errCode != 0 {
			crypto.SecureZero(k)
			return DecryptResult{}, errCode
		}
		if valid {
			key = k
			subkeyReader = sr
			break
		}
		crypto.SecureZero(k)
	}
	if key == nil {
		return DecryptResult{}, ErrWrongPassword
	}
	defer crypto.SecureZero(key)

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptMACSubkey, macSubkey)
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Derive cipher key: XOR with keyfile key when keyfiles are used.
	// HKDF/subkeys still derive from the password key.
	cipherKey := key
	if keyfileKey != nil {
		cipherKey = keyfile.XORWithKey(key, keyfileKey)
		// Register the wipe the instant the secret exists — BEFORE the fallible
		// NewCipherSuite call — so cipherKey is zeroed on EVERY return path,
		// including a NewCipherSuite error (where Close() below is never set up).
		// On success CipherSuite.Close() also wipes it (it aliases cs.key) and,
		// being registered later, runs first in LIFO order; this defer is then a
		// harmless second wipe. It is the SOLE wipe on the error path.
		defer zeroWASMSensitiveBuffer(wasmZeroingDecryptCipherKey, cipherKey)
	}

	// Create cipher suite
	cipherSuite, err := newCipherSuite(
		cipherKey,
		hdr.Nonce,
		serpentKey,
		hdr.SerpentIV,
		mac,
		subkeyReader.Reader(),
		hdr.Flags.Paranoid,
	)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptSerpentKey, serpentKey)
	if err != nil {
		return DecryptResult{}, ErrCorruptedHeader
	}
	defer cipherSuite.Close()

	// Calculate payload size
	headerSize := header.HeaderSize(len(hdr.Comments))
	payloadSize := len(volumeData) - headerSize
	if payloadSize <= 0 {
		return DecryptResult{}, ErrCorruptedHeader
	}

	// Read payload from remaining bytes
	payload := volumeData[headerSize:]

	// Decrypt payload. RS-encoded volumes are rejected by
	// hasUnsupportedWASMFeature above, so only the plain path exists here.
	var counter int64
	plaintext, err := decryptPlainPayload(payload, cipherSuite, &counter)
	if err != nil {
		return DecryptResult{}, ErrModifiedData
	}

	// Verify MAC
	computedMAC := cipherSuite.Sum()
	macValid := subtle.ConstantTimeCompare(computedMAC, hdr.AuthTag) == 1
	zeroWASMSensitiveBuffer(wasmZeroingDecryptComputedMAC, computedMAC)
	if !macValid {
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, plaintext)
		return DecryptResult{}, ErrModifiedData
	}

	return DecryptResult{Plaintext: plaintext, Comments: hdr.Comments}, 0
}

// verifyWASMHeader checks whether key authenticates the volume header and, on
// success, returns the HKDF subkey reader positioned for the remaining subkey
// reads. valid is false for a wrong key (a candidate password form that does not
// match); errCode is non-zero only for a hard failure (corrupted header), not
// for a wrong password.
func verifyWASMHeader(key []byte, hdr *header.VolumeHeader, keyfileHash []byte, isLegacyV1 bool) (valid bool, sr *crypto.SubkeyReader, errCode int) {
	if isLegacyV1 {
		// v1: verify password via SHA3-512(key); HKDF uses the plain key.
		if !header.VerifyV1Header(key, hdr).Valid {
			return false, nil, 0
		}
		hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
		return true, crypto.NewSubkeyReader(hkdfStream), 0
	}

	// v2: initialize HKDF, then verify the header MAC.
	hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
	reader := crypto.NewSubkeyReader(hkdfStream)
	subkeyHeader, err := reader.HeaderSubkey()
	if err != nil {
		return false, nil, ErrCorruptedHeader
	}
	authValid := header.VerifyV2Header(subkeyHeader, hdr, keyfileHash).Valid
	zeroWASMSensitiveBuffer(wasmZeroingDecryptHeaderSubkey, subkeyHeader)
	if !authValid {
		return false, nil, 0
	}
	return true, reader, 0
}

func hasUnsupportedWASMFeature(flags header.Flags) bool {
	return flags.ReedSolomon || flags.Padded
}

// decryptPlainPayload decrypts non-RS payload in chunks
func decryptPlainPayload(payload []byte, cs *crypto.CipherSuite, counter *int64) ([]byte, error) {
	plaintext := make([]byte, 0, len(payload))
	chunkSize := util.MiB

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := min(offset+chunkSize, len(payload))

		chunk := payload[offset:end]
		dst := make([]byte, len(chunk))
		cs.Decrypt(dst, chunk)
		plaintext = append(plaintext, dst...)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, dst)

		*counter += int64(len(chunk))

		// Rekey every 60 GiB
		if *counter >= crypto.RekeyThreshold {
			if err := cs.Rekey(); err != nil {
				return nil, err
			}
			*counter = 0
		}
	}

	return plaintext, nil
}
