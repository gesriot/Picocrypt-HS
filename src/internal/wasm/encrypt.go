package wasm

import (
	"bytes"
	"io"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
)

var writeAuthValues = header.WriteAuthValues

type byteSliceWriterAt struct {
	data []byte
}

func (w byteSliceWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(w.data)) {
		return 0, io.ErrShortWrite
	}
	start := int(off)
	if len(p) > len(w.data)-start {
		return 0, io.ErrShortWrite
	}
	copy(w.data[start:], p)
	return len(p), nil
}

// EncryptVolume encrypts plaintext data into a Picocrypt volume.
// Returns (ciphertext, 0) on success, or (nil, errorCode) on failure.
// Web version: password-only, no keyfiles, no paranoid mode, no RS on payload.
func EncryptVolume(plaintext []byte, password string) ([]byte, int) {
	// Initialize RS codecs
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Generate random cryptographic values
	salt, err := crypto.RandomBytes(header.SaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	hkdfSalt, err := crypto.RandomBytes(header.HKDFSaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	serpentIV, err := crypto.RandomBytes(header.SerpentIVSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	nonce, err := crypto.RandomBytes(header.NonceSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create header (normal mode, no keyfiles, no RS on payload)
	hdr := header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	hdr.Flags = header.Flags{
		Paranoid:       false,
		UseKeyfiles:    false,
		KeyfileOrdered: false,
		ReedSolomon:    false, // No RS on payload for web version (simpler, smaller)
		Padded:         false,
	}

	// Derive key
	key, err := crypto.DeriveKey([]byte(password), salt, false)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer crypto.SecureZero(key)

	// Initialize HKDF (v2 order: HKDF before keyfile XOR)
	hkdfStream := crypto.NewHKDFStream(key, hkdfSalt)
	subkeyReader := crypto.NewSubkeyReader(hkdfStream)

	// Read header subkey for v2 MAC
	subkeyHeader, err := subkeyReader.HeaderSubkey()
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer crypto.SecureZero(subkeyHeader)

	// Compute header MAC (no keyfiles, so keyfileHash is zeros)
	keyfileHash := make([]byte, 32)
	hdr.KeyHash = header.ComputeV2HeaderMAC(subkeyHeader, hdr, keyfileHash)
	hdr.KeyfileHash = keyfileHash

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer crypto.SecureZero(macSubkey)

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer crypto.SecureZero(serpentKey)

	// Create MAC (normal mode = BLAKE2b)
	mac, err := crypto.NewMAC(macSubkey, false)
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create cipher suite (normal mode, no Serpent)
	cipherSuite, err := crypto.NewCipherSuite(
		key,
		nonce,
		serpentKey,
		serpentIV,
		mac,
		subkeyReader.Reader(),
		false, // not paranoid
	)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer cipherSuite.Close()

	// Write header to buffer
	var headerBuf bytes.Buffer
	headerWriter := header.NewWriter(&headerBuf, rsCodecs)
	if _, err := headerWriter.WriteHeader(hdr); err != nil {
		return nil, ErrRandomFailure
	}

	// Encrypt payload
	var ciphertextBuf bytes.Buffer
	chunkSize := util.MiB
	var counter int64

	for offset := 0; offset < len(plaintext); offset += chunkSize {
		end := offset + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		chunk := plaintext[offset:end]
		dst := make([]byte, len(chunk))
		cipherSuite.Encrypt(dst, chunk)
		ciphertextBuf.Write(dst)

		counter += int64(len(chunk))

		// Rekey every 60 GiB
		if counter >= crypto.RekeyThreshold {
			if err := cipherSuite.Rekey(); err != nil {
				return nil, ErrModifiedData
			}
			counter = 0
		}
	}

	// Get final MAC
	authTag := cipherSuite.Sum()
	hdr.AuthTag = authTag

	// Now we need to patch the auth values into the header
	// The header was written with placeholders, we need to update them
	headerBytes := headerBuf.Bytes()
	if err := writeAuthValues(
		byteSliceWriterAt{data: headerBytes},
		header.AuthValuesOffset(len(hdr.Comments)),
		hdr.KeyHash,
		hdr.KeyfileHash,
		authTag,
		rsCodecs,
	); err != nil {
		return nil, ErrModifiedData
	}

	// Combine header and encrypted payload
	result := make([]byte, 0, len(headerBytes)+ciphertextBuf.Len())
	result = append(result, headerBytes...)
	result = append(result, ciphertextBuf.Bytes()...)

	return result, 0
}
