// Package crypto provides cryptographic primitives for Picocrypt volumes.
// This file contains memory zeroing utilities for secure cleanup of sensitive data.

package crypto

import (
	"crypto/subtle"
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

// Secret owns a []byte of sensitive key material and zeros it on Close().
//
// Ownership/lifetime contract:
//   - SecretFrom TAKES ownership of the passed slice; the caller MUST NOT retain
//     or mutate it afterwards.
//   - Bytes() returns a BORROW of the live backing array, valid only until
//     Close(). Callers MUST NOT append to it (append may realloc-orphan a copy)
//     nor retain it past Close().
//   - Secret is NOT safe for concurrent use; it is owned by a single operation.
type Secret struct {
	b []byte
}

// SecretFrom takes ownership of b (no copy).
func SecretFrom(b []byte) *Secret { return &Secret{b: b} }

// Bytes returns the live backing array (a borrow). Nil-safe.
func (s *Secret) Bytes() []byte {
	if s == nil {
		return nil
	}
	return s.b
}

// Len reports the secret length. Nil-safe.
func (s *Secret) Len() int {
	if s == nil {
		return 0
	}
	return len(s.b)
}

// Set zeros the current backing array and adopts b.
//
// AUDIT-CRITICAL: the pointer-identity + len==0 guard (verbatim from the former
// OperationContext.setKey, context.go) skips zeroing when b IS the current
// backing array, so a self-assign (e.g. the no-keyfile v1 decrypt path) does not
// wipe the live key.
func (s *Secret) Set(b []byte) {
	if s.b != nil && (len(b) == 0 || &b[0] != &s.b[0]) {
		SecureZero(s.b)
	}
	s.b = b
}

// Close zeros the backing array and drops it. Idempotent and nil-safe.
func (s *Secret) Close() {
	if s == nil {
		return
	}
	SecureZero(s.b)
	s.b = nil
}

// String redacts the secret so accidental %v/%s logging never leaks bytes.
func (s *Secret) String() string { return "crypto.Secret([REDACTED])" }
