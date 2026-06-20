package volume

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"reflect"
	"testing"
)

// Tripwire: every *crypto.Secret field on OperationContext must be in this set.
// Adding/removing one without wiring it through a setter + ctx.secrets registry +
// Close() (and updating this list) fails the build's tests on purpose.
func TestOperationContextSecretFieldsAreManaged(t *testing.T) {
	want := map[string]bool{"Key": true, "KeyfileKey": true, "passwordBytes": true}
	got := map[string]bool{}
	secretPtr := reflect.TypeOf((*crypto.Secret)(nil))
	typ := reflect.TypeOf(OperationContext{})
	for i := range typ.NumField() {
		if typ.Field(i).Type == secretPtr {
			got[typ.Field(i).Name] = true
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("secret fields changed: want %v got %v — wire any new *crypto.Secret "+
			"field through a setter + ctx.secrets + Close(), then update this list", want, got)
	}
}

func TestOperationContextCloseZerosAllSecrets(t *testing.T) {
	ctx := &OperationContext{}
	ctx.setKey(bytes.Repeat([]byte{0xAA}, 32))
	ctx.setKeyfileKey(bytes.Repeat([]byte{0xBB}, 32))
	ctx.setPasswordBytes(bytes.Repeat([]byte{0xCC}, 16))

	// snapshot backing arrays (still alias after Close, which zeros in place)
	snaps := map[string][]byte{
		"Key": ctx.Key.Bytes(), "KeyfileKey": ctx.KeyfileKey.Bytes(), "passwordBytes": ctx.passwordBytes.Bytes(),
	}
	ctx.Close()
	for name, b := range snaps {
		for i, x := range b {
			if x != 0 {
				t.Fatalf("%s byte %d not zeroed after Close: %d", name, i, x)
			}
		}
	}
}
