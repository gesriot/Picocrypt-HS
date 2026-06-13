package crypto

import (
	"crypto/sha3"

	"Picocrypt-NG/internal/util"

	"golang.org/x/crypto/chacha20"
)

// RekeyThreshold is the number of bytes after which rekeying must occur.
// This prevents nonce overflow in XChaCha20.
//
// It is a package-level var (not const) solely to serve as a test seam: tests
// lower it to a few MiB to exercise the >60 GiB rekey boundary on a small
// synthetic volume, then restore it via defer. The production default is
// byte-identical (60 GiB) and no production code path reassigns it.
var RekeyThreshold int64 = 60 * util.GiB

// DeniabilityRekey computes new nonce for deniability layer rekeying.
// Unlike regular rekeying which uses HKDF, deniability uses SHA3-256(nonce).
//
// CRITICAL: Deniability rekeying is DIFFERENT from regular rekeying!
// Regular: nonce from HKDF stream
// Deniability: nonce = SHA3-256(old_nonce)[:24]
func DeniabilityRekey(key, oldNonce []byte) (*chacha20.Cipher, []byte, error) {
	sum := sha3.Sum256(oldNonce)
	newNonce := append([]byte(nil), sum[:RekeyNonceSize]...)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, newNonce)
	if err != nil {
		return nil, nil, err
	}

	return cipher, newNonce, nil
}
