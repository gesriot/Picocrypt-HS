// Package crypto provides cryptographic primitives for Picocrypt volumes.
// This file contains memory zeroing utilities for secure cleanup of sensitive data.

package crypto

import (
	"crypto/subtle"
	"hash"
)

// SecureZero overwrites a byte slice with zeros to prevent sensitive data
// from persisting in memory. This helps mitigate memory dump attacks and
// reduces the window during which keys are recoverable from RAM.
//
// SECURITY NOTE: Due to Go's garbage collector and potential compiler
// optimizations, this function cannot guarantee complete erasure. However,
// it significantly reduces the attack surface compared to no cleanup.
//
// The function uses subtle.ConstantTimeCopy to prevent the compiler from
// optimizing away the zeroing operation.
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use constant-time copy from a zero slice to prevent optimization removal
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// SecureZeroMultiple zeros multiple byte slices in a single call.
// Useful for cleaning up multiple related keys or buffers.
func SecureZeroMultiple(slices ...[]byte) {
	for _, s := range slices {
		SecureZero(s)
	}
}

// SecureZeroHash resets a hash.Hash state to prevent partial hash data
// from remaining in memory. Note: not all Hash implementations may fully
// clear their internal state on Reset().
func SecureZeroHash(h hash.Hash) {
	if h != nil {
		h.Reset()
	}
}
