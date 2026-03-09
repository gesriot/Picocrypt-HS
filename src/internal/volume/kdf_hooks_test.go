package volume

import (
	"bytes"
	"testing"

	"Picocrypt-NG/internal/crypto"

	"golang.org/x/crypto/argon2"
)

func TestProductionKDFWrappersMatchCurrentImplementations(t *testing.T) {
	prevVolumeKey := deriveVolumeKey
	prevDeniabilityKey := deriveDeniabilityKey
	deriveVolumeKey = crypto.DeriveKey
	deriveDeniabilityKey = productionDeniabilityKey
	defer func() {
		deriveVolumeKey = prevVolumeKey
		deriveDeniabilityKey = prevDeniabilityKey
	}()

	password := []byte("test-password")
	salt := bytes.Repeat([]byte{0x42}, 16)

	gotNormal, err := deriveVolumeKey(password, salt, false)
	if err != nil {
		t.Fatal(err)
	}
	wantNormal, err := crypto.DeriveKey(password, salt, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNormal, wantNormal) {
		t.Fatal("normal wrapper diverged from production implementation")
	}

	gotParanoid, err := deriveVolumeKey(password, salt, true)
	if err != nil {
		t.Fatal(err)
	}
	wantParanoid, err := crypto.DeriveKey(password, salt, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotParanoid, wantParanoid) {
		t.Fatal("paranoid wrapper diverged from production implementation")
	}

	gotDeniability := deriveDeniabilityKey(password, salt)
	wantDeniability := argon2.IDKey(
		password,
		salt,
		crypto.Argon2NormalPasses,
		crypto.Argon2NormalMemory,
		crypto.Argon2NormalThreads,
		crypto.Argon2KeySize,
	)
	if !bytes.Equal(gotDeniability, wantDeniability) {
		t.Fatal("deniability wrapper diverged from production implementation")
	}
}
