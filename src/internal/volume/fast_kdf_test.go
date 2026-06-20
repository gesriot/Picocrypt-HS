package volume

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

const (
	fastTestArgon2NormalPasses    uint32 = 1
	fastTestArgon2NormalMemory    uint32 = 32 * 1024
	fastTestArgon2NormalThreads   uint8  = 1
	fastTestArgon2ParanoidPasses  uint32 = 2
	fastTestArgon2ParanoidMemory  uint32 = 64 * 1024
	fastTestArgon2ParanoidThreads uint8  = 1
)

func fastTestVolumeKey(password, salt []byte, paranoid bool) ([]byte, error) {
	passes := fastTestArgon2NormalPasses
	memory := fastTestArgon2NormalMemory
	threads := fastTestArgon2NormalThreads
	if paranoid {
		passes = fastTestArgon2ParanoidPasses
		memory = fastTestArgon2ParanoidMemory
		threads = fastTestArgon2ParanoidThreads
	}
	return argon2.IDKey(password, salt, passes, memory, threads, crypto.Argon2KeySize), nil
}

func fastTestDeniabilityKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		fastTestArgon2NormalPasses,
		fastTestArgon2NormalMemory,
		fastTestArgon2NormalThreads,
		crypto.Argon2KeySize,
	)
}

func useTestKDF(
	volumeKey func(password, salt []byte, paranoid bool) ([]byte, error),
	deniabilityKey func(password, salt []byte) []byte,
) func() {
	prevVolumeKey := deriveVolumeKey
	prevDeniabilityKey := deriveDeniabilityKey
	deriveVolumeKey = volumeKey
	deriveDeniabilityKey = deniabilityKey
	return func() {
		deriveVolumeKey = prevVolumeKey
		deriveDeniabilityKey = prevDeniabilityKey
	}
}

func useFastTestKDF() func() {
	return useTestKDF(fastTestVolumeKey, fastTestDeniabilityKey)
}

func useProductionTestKDF() func() {
	return useTestKDF(crypto.DeriveKey, productionDeniabilityKey)
}

func TestMain(m *testing.M) {
	restore := useFastTestKDF()
	code := m.Run()
	restore()
	os.Exit(code)
}

func TestFastKDFHookCanBeEnabledAndRestored(t *testing.T) {
	restoreProduction := useProductionTestKDF()
	password := []byte("test-password")
	salt := bytes.Repeat([]byte{0x24}, 16)

	before, err := deriveVolumeKey(password, salt, false)
	if err != nil {
		restoreProduction()
		t.Fatalf("production deriveVolumeKey returned error: %v", err)
	}

	restoreFast := useFastTestKDF()
	fast, err := deriveVolumeKey(password, salt, false)
	restoreFast()
	if err != nil {
		restoreProduction()
		t.Fatalf("fast deriveVolumeKey returned error: %v", err)
	}

	after, err := deriveVolumeKey(password, salt, false)
	restoreProduction()
	if err != nil {
		t.Fatalf("restored deriveVolumeKey returned error: %v", err)
	}

	if bytes.Equal(before, fast) {
		t.Fatal("fast KDF should not match production KDF for the same input")
	}

	if !bytes.Equal(before, after) {
		t.Fatal("restoring production KDF did not restore the original behavior")
	}
}
