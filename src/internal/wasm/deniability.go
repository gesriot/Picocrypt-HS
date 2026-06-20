package wasm

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"

	pwnorm "Picocrypt-NG/internal/password"

	"golang.org/x/crypto/chacha20"
)

// Outer deniability-wrapper sizes (distinct from the inner volume's header
// salt/nonce). Frozen to match desktop volume.AddDeniability.
const (
	deniabilitySaltSize  = 16
	deniabilityNonceSize = 24
)

// wrapDeniability wraps a finished inner .pcv in the outer XChaCha20 deniability
// layer: salt(16) ‖ nonce(24) ‖ keystream-XOR(inner). The outer key is derived
// with normal-params Argon2id over the NFC-normalized password — byte-identical
// to desktop volume.AddDeniability. Returns (wrapped, 0) or (nil, ErrRandomFailure).
func wrapDeniability(inner, password []byte) ([]byte, int) {
	salt, err := crypto.RandomBytes(deniabilitySaltSize)
	if err != nil {
		return nil, ErrRandomFailure
	}
	nonce, err := crypto.RandomBytes(deniabilityNonceSize)
	if err != nil {
		return nil, ErrRandomFailure
	}

	kdfInput := pwnorm.EncodeForKDF(password)
	key, err := crypto.DeriveKey(kdfInput, salt, false)
	zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKDFInput, kdfInput)
	if err != nil {
		return nil, ErrRandomFailure
	}
	defer zeroWASMSensitiveBuffer(wasmZeroingDeniabilityKey, key)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, ErrRandomFailure
	}

	out := make([]byte, 0, len(salt)+len(nonce)+len(inner))
	out = append(out, salt...)
	out = append(out, nonce...)

	// XOR the inner volume in MiB chunks, mirroring desktop's rekey boundary.
	// Under the WASM 1 GiB size cap the 60 GiB rekey threshold is never reached;
	// the counter/rekey branch is kept only for byte-format fidelity with desktop.
	var counter int64
	for offset := 0; offset < len(inner); offset += util.MiB {
		end := min(offset+util.MiB, len(inner))
		dst := make([]byte, end-offset)
		cipher.XORKeyStream(dst, inner[offset:end])
		out = append(out, dst...)
		counter += int64(end - offset)
		if counter >= crypto.RekeyThreshold {
			cipher, nonce, err = crypto.DeniabilityRekey(key, nonce)
			if err != nil {
				return nil, ErrRandomFailure
			}
			counter = 0
		}
	}
	return out, 0
}
