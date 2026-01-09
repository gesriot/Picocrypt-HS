package crypto

import (
	"bytes"
	"testing"
)

func TestSecureZero(t *testing.T) {
	// Test that SecureZero actually zeros the buffer
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	SecureZero(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("SecureZero: byte %d = %d; want 0", i, b)
		}
	}
}

func TestSecureZeroEmpty(t *testing.T) {
	// Should not panic on empty slice
	SecureZero(nil)
	SecureZero([]byte{})
}

func TestSecureZeroLarge(t *testing.T) {
	// Test with a larger buffer
	data := make([]byte, 1024*1024) // 1 MiB
	for i := range data {
		data[i] = byte(i % 256)
	}

	SecureZero(data)

	// Verify all zeros
	zeros := make([]byte, len(data))
	if !bytes.Equal(data, zeros) {
		t.Error("SecureZero did not zero all bytes in large buffer")
	}
}

func TestSecureZeroMultiple(t *testing.T) {
	slice1 := []byte{1, 2, 3}
	slice2 := []byte{4, 5, 6, 7}
	slice3 := []byte{8, 9}

	SecureZeroMultiple(slice1, slice2, slice3)

	for i, b := range slice1 {
		if b != 0 {
			t.Errorf("slice1[%d] = %d; want 0", i, b)
		}
	}
	for i, b := range slice2 {
		if b != 0 {
			t.Errorf("slice2[%d] = %d; want 0", i, b)
		}
	}
	for i, b := range slice3 {
		if b != 0 {
			t.Errorf("slice3[%d] = %d; want 0", i, b)
		}
	}
}

func TestSecureZeroMultipleEmpty(t *testing.T) {
	// Should not panic on empty or nil slices
	SecureZeroMultiple()
	SecureZeroMultiple(nil)
	SecureZeroMultiple(nil, []byte{}, nil)
}

func TestSecureZeroHash(t *testing.T) {
	// SecureZeroHash should not panic on nil
	SecureZeroHash(nil)

	// Test with actual hash (just check it doesn't panic)
	mac, _ := NewMAC(make([]byte, 32), false)
	mac.Write([]byte("test data"))
	SecureZeroHash(mac)
}

func TestKeyMaterial(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	km := NewKeyMaterial(data)

	// Bytes should return the data
	if !bytes.Equal(km.Bytes(), data) {
		t.Error("Bytes() should return equivalent data")
	}

	// Data should be a copy, not the same slice
	if &km.Bytes()[0] == &data[0] {
		t.Error("KeyMaterial should make a copy of data")
	}

	// Len should match
	if km.Len() != len(data) {
		t.Errorf("Len() = %d; want %d", km.Len(), len(data))
	}

	// IsClosed should be false
	if km.IsClosed() {
		t.Error("IsClosed() should be false before Close()")
	}
}

func TestKeyMaterialClose(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	km := NewKeyMaterial(data)
	internalData := km.Bytes()

	km.Close()

	// After close:
	// - IsClosed should be true
	if !km.IsClosed() {
		t.Error("IsClosed() should be true after Close()")
	}

	// - Bytes should return nil
	if km.Bytes() != nil {
		t.Error("Bytes() should return nil after Close()")
	}

	// - Len should be 0
	if km.Len() != 0 {
		t.Errorf("Len() = %d; want 0 after Close()", km.Len())
	}

	// - Original data slice should be zeroed
	zeros := make([]byte, len(internalData))
	if !bytes.Equal(internalData, zeros) {
		t.Error("Internal data should be zeroed after Close()")
	}
}

func TestKeyMaterialCloseIdempotent(t *testing.T) {
	km := NewKeyMaterial([]byte{1, 2, 3, 4})

	// Multiple Close() calls should be safe
	km.Close()
	km.Close()
	km.Close()

	if !km.IsClosed() {
		t.Error("Should remain closed after multiple Close() calls")
	}
}

func TestKeyMaterialNil(t *testing.T) {
	km := NewKeyMaterial(nil)

	if km.Bytes() != nil {
		t.Error("Bytes() should return nil for nil input")
	}

	if km.Len() != 0 {
		t.Error("Len() should be 0 for nil input")
	}

	// Close should not panic
	km.Close()
}

func TestCryptoContext(t *testing.T) {
	cc := &CryptoContext{
		Key:          []byte{1, 2, 3, 4},
		KeyfileKey:   []byte{5, 6, 7, 8},
		MacSubkey:    []byte{9, 10, 11, 12},
		SerpentKey:   []byte{13, 14, 15, 16},
		HeaderSubkey: []byte{17, 18, 19, 20},
	}

	// Save references to check zeroing
	keyRef := cc.Key
	keyfileRef := cc.KeyfileKey
	macRef := cc.MacSubkey
	serpentRef := cc.SerpentKey
	headerRef := cc.HeaderSubkey

	cc.Close()

	// All fields should be nil
	if cc.Key != nil {
		t.Error("Key should be nil after Close()")
	}
	if cc.KeyfileKey != nil {
		t.Error("KeyfileKey should be nil after Close()")
	}
	if cc.MacSubkey != nil {
		t.Error("MacSubkey should be nil after Close()")
	}
	if cc.SerpentKey != nil {
		t.Error("SerpentKey should be nil after Close()")
	}
	if cc.HeaderSubkey != nil {
		t.Error("HeaderSubkey should be nil after Close()")
	}

	// Original slices should be zeroed
	zeros4 := make([]byte, 4)
	if !bytes.Equal(keyRef, zeros4) {
		t.Error("Key data should be zeroed")
	}
	if !bytes.Equal(keyfileRef, zeros4) {
		t.Error("KeyfileKey data should be zeroed")
	}
	if !bytes.Equal(macRef, zeros4) {
		t.Error("MacSubkey data should be zeroed")
	}
	if !bytes.Equal(serpentRef, zeros4) {
		t.Error("SerpentKey data should be zeroed")
	}
	if !bytes.Equal(headerRef, zeros4) {
		t.Error("HeaderSubkey data should be zeroed")
	}
}

func TestCryptoContextCloseIdempotent(t *testing.T) {
	cc := &CryptoContext{
		Key: []byte{1, 2, 3, 4},
	}

	// Multiple Close() calls should be safe
	cc.Close()
	cc.Close()
	cc.Close()
}

func TestCryptoContextNilFields(t *testing.T) {
	// Close should handle nil fields gracefully
	cc := &CryptoContext{}
	cc.Close() // Should not panic
}
