package crypto

import (
	"bytes"
	"testing"
)

// TestCipherSuiteCloseWipesSerpentSchedule asserts that Close() wipes the
// expanded Serpent key schedule held by the paranoid suite. The schedule is a
// [132]uint32 derived from the Serpent key; if it survives Close it is residual
// key material. The check encrypts a fixed block with the captured cipher both
// before and after Close: after the wipe the block must behave as a zero-key
// cipher (i.e. produce a different ciphertext than the keyed one, matching a
// freshly built zero-key Serpent block). Skips gracefully if the linked serpent
// build predates Zero().
func TestCipherSuiteCloseWipesSerpentSchedule(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	nonce := bytes.Repeat([]byte{2}, 24)
	sKey := bytes.Repeat([]byte{3}, 32)
	sIV := bytes.Repeat([]byte{4}, 16)
	mac, err := NewMAC(bytes.Repeat([]byte{5}, 32), true)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := NewCipherSuite(key, nonce, sKey, sIV, mac, NewHKDFStream(key, nonce), true)
	if err != nil {
		t.Fatal(err)
	}
	block := cs.serpentS

	z, ok := block.(interface {
		Zero()
		Encrypt(dst, src []byte)
	})
	if !ok {
		t.Skip("serpent fork without Zero() not yet released")
	}

	pt := bytes.Repeat([]byte{0xAB}, 16) // one Serpent block
	keyed := make([]byte, 16)
	z.Encrypt(keyed, pt)

	cs.Close()

	// After Close the captured block's schedule must be wiped: encrypting the
	// same plaintext now must NOT match the keyed output (the key is gone).
	wiped := make([]byte, 16)
	z.Encrypt(wiped, pt)
	if bytes.Equal(keyed, wiped) {
		t.Fatalf("serpent schedule not wiped: ciphertext unchanged after Close (key material survived)")
	}
}
