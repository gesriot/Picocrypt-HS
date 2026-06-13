// Package wasm provides memory-based encryption/decryption for WASM builds.
package wasm

import (
	"bytes"
	"crypto/subtle"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
)

// Error codes matching website convention
const (
	ErrUnsupported     = 1 // Keyfiles required, deniability, split chunks
	ErrCorruptedHeader = 2 // RS decode failure
	ErrWrongPassword   = 3 // Auth verification failed
	ErrModifiedData    = 4 // Payload MAC mismatch
	ErrRandomFailure   = 5 // Random generation failed (encrypt only)
)

// DecryptVolume decrypts a Picocrypt volume from memory.
// Returns (plaintext, 0) on success, or (nil, errorCode) on failure.
func DecryptVolume(volumeData []byte, password string) ([]byte, int) {
	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return nil, ErrCorruptedHeader
	}

	// Create reader from volume data
	reader := bytes.NewReader(volumeData)

	// Read header
	headerReader := header.NewReader(reader, rsCodecs)
	result, err := headerReader.ReadHeader()
	if err != nil {
		return nil, ErrCorruptedHeader
	}
	hdr := result.Header

	// Check for unsupported features
	if hasUnsupportedWASMFeature(hdr.Flags) {
		return nil, ErrUnsupported
	}

	// Derive key
	passwordBytes := []byte(password)
	key, err := crypto.DeriveKey(passwordBytes, hdr.Salt, hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptPasswordBytes, passwordBytes)
	if err != nil {
		return nil, ErrCorruptedHeader
	}
	defer crypto.SecureZero(key)

	// Prepare keyfile hash (zeros since no keyfiles)
	keyfileHash := make([]byte, 32)
	defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileHash, keyfileHash)

	// Initialize HKDF and verify auth based on version
	var subkeyReader *crypto.SubkeyReader
	isLegacyV1 := hdr.IsLegacyV1()

	if isLegacyV1 {
		// v1: Verify password using SHA3-512(key), HKDF uses plain key
		authResult := header.VerifyV1Header(key, hdr)
		if !authResult.Valid {
			return nil, ErrWrongPassword
		}

		// v1: HKDF with plain key (no keyfile XOR since web doesn't support keyfiles)
		hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
		subkeyReader = crypto.NewSubkeyReader(hkdfStream)
	} else {
		// v2: Initialize HKDF first, then verify header MAC
		hkdfStream := crypto.NewHKDFStream(key, hdr.HKDFSalt)
		subkeyReader = crypto.NewSubkeyReader(hkdfStream)

		// Read header subkey for verification
		subkeyHeader, err := subkeyReader.HeaderSubkey()
		if err != nil {
			return nil, ErrCorruptedHeader
		}

		// Verify header MAC
		authResult := header.VerifyV2Header(subkeyHeader, hdr, keyfileHash)
		zeroWASMSensitiveBuffer(wasmZeroingDecryptHeaderSubkey, subkeyHeader)
		if !authResult.Valid {
			return nil, ErrWrongPassword
		}
	}

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return nil, ErrCorruptedHeader
	}

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return nil, ErrCorruptedHeader
	}

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, hdr.Flags.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptMACSubkey, macSubkey)
	if err != nil {
		return nil, ErrCorruptedHeader
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		key,
		hdr.Nonce,
		serpentKey,
		hdr.SerpentIV,
		mac,
		subkeyReader.Reader(),
		hdr.Flags.Paranoid,
	)
	zeroWASMSensitiveBuffer(wasmZeroingDecryptSerpentKey, serpentKey)
	if err != nil {
		return nil, ErrCorruptedHeader
	}
	defer cipherSuite.Close()

	// Calculate payload size
	headerSize := header.HeaderSize(len(hdr.Comments))
	payloadSize := len(volumeData) - headerSize
	if payloadSize <= 0 {
		return nil, ErrCorruptedHeader
	}

	// Read payload from remaining bytes
	payload := volumeData[headerSize:]

	// Decrypt payload. RS-encoded volumes are rejected by
	// hasUnsupportedWASMFeature above, so only the plain path exists here.
	var counter int64
	plaintext, err := decryptPlainPayload(payload, cipherSuite, &counter)
	if err != nil {
		return nil, ErrModifiedData
	}

	// Verify MAC
	computedMAC := cipherSuite.Sum()
	macValid := subtle.ConstantTimeCompare(computedMAC, hdr.AuthTag) == 1
	zeroWASMSensitiveBuffer(wasmZeroingDecryptComputedMAC, computedMAC)
	if !macValid {
		zeroWASMSensitiveBuffer(wasmZeroingDecryptPlaintextChunk, plaintext)
		return nil, ErrModifiedData
	}

	return plaintext, 0
}

func hasUnsupportedWASMFeature(flags header.Flags) bool {
	return flags.Paranoid ||
		flags.UseKeyfiles ||
		flags.KeyfileOrdered ||
		flags.ReedSolomon ||
		flags.Padded
}

// decryptPlainPayload decrypts non-RS payload in chunks
func decryptPlainPayload(payload []byte, cs *crypto.CipherSuite, counter *int64) ([]byte, error) {
	plaintext := make([]byte, 0, len(payload))
	chunkSize := util.MiB

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}

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
