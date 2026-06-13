package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/chacha20"
)

// TestParanoidCipherSuiteGoldenVector is a known-answer vector for the paranoid
// cipher layer (Serpent-CTR + XChaCha20) at the crypto-unit boundary.
//
// COMMUTATIVITY NOTE: Serpent-CTR and XChaCha20 are BOTH keystream-XOR stream
// ciphers whose keystreams are independent of the data, so the layer computes
//
//	ct = pt XOR serpentKeystream XOR chachaKeystream
//
// and XOR is commutative — applying Serpent-then-XChaCha20 yields byte-identical
// output to XChaCha20-then-Serpent. The application *order* therefore cannot be,
// and need not be, distinguished from the ciphertext (a swap is a no-op for the
// output, the MAC, and cross-version interop). What this vector DOES pin is the
// combined keystream: it fails if either cipher's keystream drifts — a cipher
// library swap, a wrong key/nonce/IV wiring, or a parameter change — none of which
// the existing reversible roundtrip test (TestCipherSuiteEncryptDecrypt) can catch.
// The expected value is composed independently from the raw primitives and is also
// frozen as a hex anchor.
func TestParanoidCipherSuiteGoldenVector(t *testing.T) {
	// Fixed, distinct inputs (deterministic known-answer vector).
	key := make([]byte, 32)        // XChaCha20 key
	nonce := make([]byte, 24)      // 24-byte nonce => XChaCha20
	serpentKey := make([]byte, 32) // Serpent key
	serpentIV := make([]byte, 16)  // Serpent-CTR IV
	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(0x40 + i)
	}
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
	}
	for i := range serpentIV {
		serpentIV[i] = byte(0x80 + i)
	}
	plaintext := []byte("Picocrypt paranoid layer known-answer vector.")

	// Production path: CipherSuite in paranoid mode.
	mac, err := NewMAC(make([]byte, 32), true)
	if err != nil {
		t.Fatalf("NewMAC: %v", err)
	}
	hkdf := NewHKDFStream(key, make([]byte, 32))
	suite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, mac, hkdf, true)
	if err != nil {
		t.Fatalf("NewCipherSuite: %v", err)
	}
	got := make([]byte, len(plaintext))
	srcCopy := append([]byte(nil), plaintext...) // Encrypt mutates src in-place
	suite.Encrypt(got, srcCopy)

	// Independently compose the paranoid layer with the documented parameters.
	// (Order is irrelevant by commutativity; we apply Serpent-CTR then XChaCha20 to
	// mirror the production code for readability.)
	want := composeXChaCha20(t, key, nonce, composeSerpentCTR(t, serpentKey, serpentIV, plaintext))
	if !bytes.Equal(got, want) {
		t.Fatalf("CipherSuite paranoid output != independent Serpent-CTR/XChaCha20 composition:\n got  = %x\n want = %x", got, want)
	}

	// Frozen golden anchor on the concrete combined-keystream ciphertext.
	const wantHex = "a075d0f795f065c8e2c42ae6bf03cce48c9c4fd939c08e2f18942bc995674d16b979b43b1c62ba76ac63af9d5d"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("paranoid ciphertext drifted from frozen vector:\n got  = %s\n want = %s", hex.EncodeToString(got), wantHex)
	}
}

func composeSerpentCTR(t *testing.T, key, iv, src []byte) []byte {
	t.Helper()
	block, err := serpent.NewCipher(key)
	if err != nil {
		t.Fatalf("serpent.NewCipher: %v", err)
	}
	out := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(out, src)
	return out
}

func composeXChaCha20(t *testing.T, key, nonce, src []byte) []byte {
	t.Helper()
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatalf("chacha20.NewUnauthenticatedCipher: %v", err)
	}
	out := make([]byte, len(src))
	c.XORKeyStream(out, src)
	return out
}
