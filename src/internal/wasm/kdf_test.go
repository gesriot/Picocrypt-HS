package wasm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

const fastTestWASMKDFDomain = "Picocrypt-NG internal/wasm test KDF v1"

var productionTestWASMKey func(password, salt []byte, paranoid bool) ([]byte, error)

func fastTestWASMKey(password, salt []byte, paranoid bool) ([]byte, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(fastTestWASMKDFDomain))

	var lengthBytes [8]byte
	binary.BigEndian.PutUint64(lengthBytes[:], uint64(len(password)))
	_, _ = h.Write(lengthBytes[:])
	binary.BigEndian.PutUint64(lengthBytes[:], uint64(len(salt)))
	_, _ = h.Write(lengthBytes[:])

	_, _ = h.Write(password)
	_, _ = h.Write(salt)
	paranoidByte := byte(0)
	if paranoid {
		paranoidByte = 1
	}
	_, _ = h.Write([]byte{paranoidByte})
	return h.Sum(nil), nil
}

func swapWASMTestKDF(kdf func(password, salt []byte, paranoid bool) ([]byte, error)) func() {
	previous := deriveWASMKey
	deriveWASMKey = kdf
	return func() {
		deriveWASMKey = previous
	}
}

func useProductionTestWASMKDF(t *testing.T) {
	t.Helper()
	t.Cleanup(swapWASMTestKDF(productionTestWASMKey))
}

func TestMain(m *testing.M) {
	productionTestWASMKey = deriveWASMKey
	restore := swapWASMTestKDF(fastTestWASMKey)
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestEncryptVolumeKDFErrorReturnsRandomFailure(t *testing.T) {
	sentinelErr := errors.New("injected KDF failure")
	previous := deriveWASMKey
	deriveWASMKey = func([]byte, []byte, bool) ([]byte, error) {
		return nil, sentinelErr
	}
	t.Cleanup(func() {
		deriveWASMKey = previous
	})

	ciphertext, code := EncryptVolume(
		[]byte("plaintext"),
		[]byte("password"),
		EncryptOptions{},
	)
	if code != ErrRandomFailure {
		t.Fatalf("EncryptVolume error code = %d; want ErrRandomFailure (%d)", code, ErrRandomFailure)
	}
	if ciphertext != nil {
		t.Fatalf("EncryptVolume returned %d ciphertext bytes after KDF failure; want none", len(ciphertext))
	}
}
