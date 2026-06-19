package wasm

import (
	"bytes"
	"io"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	pwnorm "Picocrypt-NG/internal/password"
	"Picocrypt-NG/internal/util"
)

var writeAuthValues = header.WriteAuthValues

type wasmZeroingBufferKind string

const (
	wasmZeroingPasswordBytes         wasmZeroingBufferKind = "password bytes"
	wasmZeroingHeaderSubkey          wasmZeroingBufferKind = "header subkey"
	wasmZeroingMACSubkey             wasmZeroingBufferKind = "mac subkey"
	wasmZeroingSerpentKey            wasmZeroingBufferKind = "serpent key"
	wasmZeroingCiphertextChunk       wasmZeroingBufferKind = "ciphertext chunk"
	wasmZeroingCiphertextBuffer      wasmZeroingBufferKind = "ciphertext buffer"
	wasmZeroingKeyfileHash           wasmZeroingBufferKind = "keyfile hash placeholder"
	wasmZeroingHeaderKeyHash         wasmZeroingBufferKind = "header auth value"
	wasmZeroingAuthTag               wasmZeroingBufferKind = "payload auth value"
	wasmZeroingHeaderBuffer          wasmZeroingBufferKind = "header buffer"
	wasmZeroingDecryptPasswordBytes  wasmZeroingBufferKind = "decrypt password bytes"
	wasmZeroingDecryptKeyfileHash    wasmZeroingBufferKind = "decrypt keyfile hash placeholder"
	wasmZeroingDecryptHeaderSubkey   wasmZeroingBufferKind = "decrypt header subkey"
	wasmZeroingDecryptMACSubkey      wasmZeroingBufferKind = "decrypt mac subkey"
	wasmZeroingDecryptSerpentKey     wasmZeroingBufferKind = "decrypt serpent key"
	wasmZeroingDecryptPlaintextChunk wasmZeroingBufferKind = "decrypt plaintext chunk"
	wasmZeroingDecryptComputedMAC    wasmZeroingBufferKind = "decrypt computed mac"
)

type wasmZeroingEvent struct {
	Kind       wasmZeroingBufferKind
	Len        int
	WasNonZero bool
	Zeroed     bool
}

// wasmZeroingObserver is a package-local test seam. It is nil in production and
// records only aggregate zeroing state, never buffer contents.
var wasmZeroingObserver func(wasmZeroingEvent)

func zeroWASMSensitiveBuffer(kind wasmZeroingBufferKind, b []byte) {
	if len(b) == 0 {
		return
	}
	wasNonZero := hasNonZeroByte(b)
	crypto.SecureZero(b)
	zeroed := !hasNonZeroByte(b)
	if wasmZeroingObserver != nil {
		wasmZeroingObserver(wasmZeroingEvent{
			Kind:       kind,
			Len:        len(b),
			WasNonZero: wasNonZero,
			Zeroed:     zeroed,
		})
	}
}

func hasNonZeroByte(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}

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

// EncryptOptions configures an in-memory encryption. Zero value = normal,
// no-comment volume (the pre-P0 behavior).
type EncryptOptions struct {
	Paranoid bool   // 8 Argon2 passes, Serpent-CTR + XChaCha20, HMAC-SHA3
	Comments string // plaintext header comments (NOT encrypted); len <= header.MaxCommentLen
}

// EncryptVolume encrypts plaintext data into a Picocrypt volume.
// Returns (ciphertext, 0) on success, or (nil, errorCode) on failure.
func EncryptVolume(plaintext, password []byte, opts EncryptOptions) ([]byte, int) {
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

	// Create header; flags/comments come from opts.
	hdr := header.NewVolumeHeader(salt, hkdfSalt, serpentIV, nonce)
	hdr.Flags = header.Flags{
		Paranoid:       opts.Paranoid,
		UseKeyfiles:    false, // P1
		KeyfileOrdered: false, // P1
		ReedSolomon:    false, // P2
		Padded:         false, // P2
	}
	hdr.Comments = opts.Comments

	// Derive key from the NFC-normalized password (#19) so web-encrypted
	// volumes are cross-platform-decryptable regardless of how it was typed.
	passwordBytes := pwnorm.EncodeForKDF(password)
	key, err := crypto.DeriveKey(passwordBytes, salt, opts.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingPasswordBytes, passwordBytes)
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

	// Compute header MAC (no keyfiles, so keyfileHash is zeros)
	keyfileHash := make([]byte, 32)
	keyfileHashZeroed := false
	defer func() {
		if !keyfileHashZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingKeyfileHash, keyfileHash)
		}
	}()
	hdr.KeyHash = header.ComputeV2HeaderMAC(subkeyHeader, hdr, keyfileHash)
	headerKeyHash := hdr.KeyHash
	headerKeyHashZeroed := false
	defer func() {
		if !headerKeyHashZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingHeaderKeyHash, headerKeyHash)
		}
	}()
	zeroWASMSensitiveBuffer(wasmZeroingHeaderSubkey, subkeyHeader)
	hdr.KeyfileHash = keyfileHash

	// Read remaining subkeys
	macSubkey, err := subkeyReader.MACSubkey()
	if err != nil {
		return nil, ErrRandomFailure
	}

	serpentKey, err := subkeyReader.SerpentKey()
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create MAC
	mac, err := crypto.NewMAC(macSubkey, opts.Paranoid)
	zeroWASMSensitiveBuffer(wasmZeroingMACSubkey, macSubkey)
	if err != nil {
		return nil, ErrRandomFailure
	}

	// Create cipher suite
	cipherSuite, err := crypto.NewCipherSuite(
		key,
		nonce,
		serpentKey,
		serpentIV,
		mac,
		subkeyReader.Reader(),
		opts.Paranoid,
	)
	zeroWASMSensitiveBuffer(wasmZeroingSerpentKey, serpentKey)
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
	headerBufferZeroed := false
	defer func() {
		if !headerBufferZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingHeaderBuffer, headerBuf.Bytes())
		}
	}()

	// Encrypt payload
	var ciphertextBuf bytes.Buffer
	ciphertextBufferZeroed := false
	defer func() {
		if !ciphertextBufferZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingCiphertextBuffer, ciphertextBuf.Bytes())
		}
	}()
	chunkSize := util.MiB
	var counter int64

	for offset := 0; offset < len(plaintext); offset += chunkSize {
		end := min(offset+chunkSize, len(plaintext))

		// Copy chunk: paranoid Encrypt mutates src (Serpent intermediate), which
		// would corrupt the caller's plaintext buffer if we passed a slice of it.
		chunk := make([]byte, end-offset)
		copy(chunk, plaintext[offset:end])
		dst := make([]byte, len(chunk))
		cipherSuite.Encrypt(dst, chunk)
		crypto.SecureZero(chunk)
		ciphertextBuf.Write(dst)
		zeroWASMSensitiveBuffer(wasmZeroingCiphertextChunk, dst)

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
	authTagZeroed := false
	defer func() {
		if !authTagZeroed {
			zeroWASMSensitiveBuffer(wasmZeroingAuthTag, authTag)
		}
	}()
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
	zeroWASMSensitiveBuffer(wasmZeroingKeyfileHash, keyfileHash)
	keyfileHashZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingHeaderKeyHash, hdr.KeyHash)
	headerKeyHashZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingAuthTag, authTag)
	authTagZeroed = true

	// Combine header and encrypted payload
	ciphertextBytes := ciphertextBuf.Bytes()
	result := make([]byte, 0, len(headerBytes)+len(ciphertextBytes))
	result = append(result, headerBytes...)
	result = append(result, ciphertextBytes...)
	zeroWASMSensitiveBuffer(wasmZeroingHeaderBuffer, headerBytes)
	headerBufferZeroed = true
	zeroWASMSensitiveBuffer(wasmZeroingCiphertextBuffer, ciphertextBytes)
	ciphertextBufferZeroed = true

	return result, 0
}
