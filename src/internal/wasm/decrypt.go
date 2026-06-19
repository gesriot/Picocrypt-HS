// Package wasm provides memory-based encryption/decryption for WASM builds.
package wasm

import (
	"bytes"
	"crypto/subtle"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
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

// DecryptVolume decrypts a Picocrypt volume from memory.
// Returns (DecryptResult, 0) on success, or (zero, errorCode) on failure.
func DecryptVolume(volumeData, password []byte) (DecryptResult, int) {
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

	// Prepare keyfile hash (zeros since no keyfiles)
	keyfileHash := make([]byte, 32)
	defer zeroWASMSensitiveBuffer(wasmZeroingDecryptKeyfileHash, keyfileHash)

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
	return flags.UseKeyfiles ||
		flags.KeyfileOrdered ||
		flags.ReedSolomon ||
		flags.Padded
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
