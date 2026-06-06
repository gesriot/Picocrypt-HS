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

// Counter tracks bytes processed and triggers rekeying at the threshold.
type Counter struct {
	count     int64
	threshold int64
}

// NewCounter creates a new byte counter with the standard 60 GiB threshold.
func NewCounter() *Counter {
	return &Counter{
		count:     0,
		threshold: RekeyThreshold,
	}
}

// Add increments the counter by n bytes.
// Returns true if rekeying is required (threshold reached).
func (c *Counter) Add(n int) bool {
	c.count += int64(n)
	return c.count >= c.threshold
}

// Reset resets the counter to zero (after rekeying).
func (c *Counter) Reset() {
	c.count = 0
}

// Count returns the current byte count.
func (c *Counter) Count() int64 {
	return c.count
}

// DeniabilityRekey computes new nonce for deniability layer rekeying.
// Unlike regular rekeying which uses HKDF, deniability uses SHA3-256(nonce).
//
// CRITICAL: Deniability rekeying is DIFFERENT from regular rekeying!
// Regular: nonce from HKDF stream
// Deniability: nonce = SHA3-256(old_nonce)[:24]
func DeniabilityRekey(key, oldNonce []byte) (*chacha20.Cipher, []byte, error) {
	sum := sha3.Sum256(oldNonce)
	newNonce := append([]byte(nil), sum[:24]...)

	cipher, err := chacha20.NewUnauthenticatedCipher(key, newNonce)
	if err != nil {
		return nil, nil, err
	}

	return cipher, newNonce, nil
}
