package wasm

import (
	"bytes"
	"io"

	"Picocrypt-NG/internal/keyfile"
)

// processWASMKeyfiles hashes the in-memory keyfiles via the shared reader-based
// core. Returns the keyfile Result and 0, or nil and a wasm error code. An
// all-zero XOR key (even number of identical keyfiles) is rejected as
// ErrKeyfilesDuplicate, matching the desktop guard.
func processWASMKeyfiles(keyfiles [][]byte, ordered bool) (*keyfile.Result, int) {
	readers := make([]io.Reader, len(keyfiles))
	for i, kf := range keyfiles {
		readers[i] = bytes.NewReader(kf)
	}
	res, err := keyfile.ProcessReaders(readers, ordered)
	if err != nil {
		return nil, ErrRandomFailure
	}
	if keyfile.IsDuplicateKeyfileKey(res.Key) {
		return nil, ErrKeyfilesDuplicate
	}
	return res, 0
}
