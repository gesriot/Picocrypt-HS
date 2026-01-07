package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	// Normal mode
	key1, err := DeriveKey(password, salt, false)
	if err != nil {
		t.Fatalf("DeriveKey(paranoid=false) failed: %v", err)
	}
	if len(key1) != Argon2KeySize {
		t.Errorf("Key length = %d; want %d", len(key1), Argon2KeySize)
	}

	// Paranoid mode
	key2, err := DeriveKey(password, salt, true)
	if err != nil {
		t.Fatalf("DeriveKey(paranoid=true) failed: %v", err)
	}
	if len(key2) != Argon2KeySize {
		t.Errorf("Key length = %d; want %d", len(key2), Argon2KeySize)
	}

	// Keys should be different (different parameters)
	if bytes.Equal(key1, key2) {
		t.Error("Normal and paranoid keys should be different")
	}

	// Same inputs should produce same outputs (deterministic)
	key1b, _ := DeriveKey(password, salt, false)
	if !bytes.Equal(key1, key1b) {
		t.Error("Same inputs should produce same key")
	}
}

func TestSubkeyReader(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
		salt[i] = byte(255 - i)
	}

	hkdf := NewHKDFStream(key, salt)
	reader := NewSubkeyReader(hkdf)

	// Read header subkey
	headerKey, err := reader.HeaderSubkey()
	if err != nil {
		t.Fatalf("HeaderSubkey() failed: %v", err)
	}
	if len(headerKey) != SubkeyHeaderSize {
		t.Errorf("Header subkey length = %d; want %d", len(headerKey), SubkeyHeaderSize)
	}

	// Should fail on second call
	_, err = reader.HeaderSubkey()
	if err == nil {
		t.Error("Second HeaderSubkey() should fail")
	}

	// Read MAC subkey
	macKey, err := reader.MACSubkey()
	if err != nil {
		t.Fatalf("MACSubkey() failed: %v", err)
	}
	if len(macKey) != SubkeyMACSize {
		t.Errorf("MAC subkey length = %d; want %d", len(macKey), SubkeyMACSize)
	}

	// Read Serpent key
	serpentKey, err := reader.SerpentKey()
	if err != nil {
		t.Fatalf("SerpentKey() failed: %v", err)
	}
	if len(serpentKey) != SubkeySerpentSize {
		t.Errorf("Serpent key length = %d; want %d", len(serpentKey), SubkeySerpentSize)
	}

	// Read rekey values
	nonce, iv, err := reader.RekeyValues()
	if err != nil {
		t.Fatalf("RekeyValues() failed: %v", err)
	}
	if len(nonce) != RekeyNonceSize {
		t.Errorf("Rekey nonce length = %d; want %d", len(nonce), RekeyNonceSize)
	}
	if len(iv) != RekeyIVSize {
		t.Errorf("Rekey IV length = %d; want %d", len(iv), RekeyIVSize)
	}

	if reader.RekeyCount() != 1 {
		t.Errorf("RekeyCount = %d; want 1", reader.RekeyCount())
	}
}

func TestSubkeyReaderOrdering(t *testing.T) {
	key := make([]byte, 32)
	salt := make([]byte, 32)

	hkdf := NewHKDFStream(key, salt)
	reader := NewSubkeyReader(hkdf)

	// Try to read Serpent key before MAC key (should fail)
	_, err := reader.SerpentKey()
	if err == nil {
		t.Error("SerpentKey() before MACSubkey() should fail")
	}
}

func TestNewMAC(t *testing.T) {
	subkey := make([]byte, 32)
	for i := range subkey {
		subkey[i] = byte(i)
	}

	// Normal mode (BLAKE2b)
	mac1, err := NewMAC(subkey, false)
	if err != nil {
		t.Fatalf("NewMAC(paranoid=false) failed: %v", err)
	}
	mac1.Write([]byte("test data"))
	sum1 := mac1.Sum(nil)
	if len(sum1) != MACSize {
		t.Errorf("MAC size = %d; want %d", len(sum1), MACSize)
	}

	// Paranoid mode (HMAC-SHA3)
	mac2, err := NewMAC(subkey, true)
	if err != nil {
		t.Fatalf("NewMAC(paranoid=true) failed: %v", err)
	}
	mac2.Write([]byte("test data"))
	sum2 := mac2.Sum(nil)
	if len(sum2) != MACSize {
		t.Errorf("MAC size = %d; want %d", len(sum2), MACSize)
	}

	// Different modes should produce different MACs
	if bytes.Equal(sum1, sum2) {
		t.Error("BLAKE2b and HMAC-SHA3 should produce different MACs")
	}
}

func TestCounter(t *testing.T) {
	c := NewCounter()

	// Should not trigger rekey initially
	if c.Add(1000) {
		t.Error("Should not trigger rekey for small amounts")
	}

	// Reset
	c.Reset()
	if c.Count() != 0 {
		t.Error("Counter should be 0 after reset")
	}
}

func TestDeniabilityRekey(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i * 2)
	}

	cipher, newNonce, err := DeniabilityRekey(key, nonce)
	if err != nil {
		t.Fatalf("DeniabilityRekey() failed: %v", err)
	}

	if cipher == nil {
		t.Error("Cipher should not be nil")
	}

	if len(newNonce) != 24 {
		t.Errorf("New nonce length = %d; want 24", len(newNonce))
	}

	// New nonce should be different from old
	if bytes.Equal(nonce, newNonce) {
		t.Error("New nonce should be different from old nonce")
	}

	// Same inputs should produce same outputs (deterministic)
	_, newNonce2, _ := DeniabilityRekey(key, nonce)
	if !bytes.Equal(newNonce, newNonce2) {
		t.Error("DeniabilityRekey should be deterministic")
	}
}

func TestCipherSuiteEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 24)
	serpentKey := make([]byte, 32)
	serpentIV := make([]byte, 16)
	hkdfSalt := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
		serpentKey[i] = byte(i + 32)
	}
	for i := range nonce {
		nonce[i] = byte(i + 64)
	}
	for i := range serpentIV {
		serpentIV[i] = byte(i + 88)
	}

	plaintext := []byte("Hello, World! This is a test message for encryption.")

	// Test both normal and paranoid modes
	for _, paranoid := range []bool{false, true} {
		t.Run(func() string {
			if paranoid {
				return "paranoid"
			}
			return "normal"
		}(), func(t *testing.T) {
			// Create MAC for encryption
			macKey := make([]byte, 32)
			encMAC, _ := NewMAC(macKey, paranoid)

			// Create cipher suite for encryption
			hkdfEnc := NewHKDFStream(key, hkdfSalt)
			encSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, encMAC, hkdfEnc, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Make a copy of plaintext for encryption (encrypt modifies src in paranoid mode)
			src := make([]byte, len(plaintext))
			copy(src, plaintext)

			// Encrypt
			ciphertext := make([]byte, len(plaintext))
			encSuite.Encrypt(ciphertext, src)

			// Ciphertext should be different from original plaintext
			if bytes.Equal(ciphertext, plaintext) {
				t.Error("Ciphertext should be different from plaintext")
			}

			// Create MAC for decryption (fresh instance)
			decMAC, _ := NewMAC(macKey, paranoid)

			// Create cipher suite for decryption
			hkdfDec := NewHKDFStream(key, hkdfSalt)
			decSuite, err := NewCipherSuite(key, nonce, serpentKey, serpentIV, decMAC, hkdfDec, paranoid)
			if err != nil {
				t.Fatalf("NewCipherSuite() failed: %v", err)
			}

			// Make a copy of ciphertext for decryption (decrypt modifies src in paranoid mode)
			encData := make([]byte, len(ciphertext))
			copy(encData, ciphertext)

			// Decrypt
			decrypted := make([]byte, len(encData))
			decSuite.Decrypt(decrypted, encData)

			// Decrypted should match original plaintext
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decrypted = %q; want %q", decrypted, plaintext)
			}

			// MACs should match
			encSum := encSuite.Sum()
			decSum := decSuite.Sum()
			if !bytes.Equal(encSum, decSum) {
				t.Error("Encryption and decryption MACs should match")
			}
		})
	}
}
