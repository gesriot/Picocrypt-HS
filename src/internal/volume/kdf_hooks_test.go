package volume

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestProductionDeniabilityKeyMatchesFrozenVector(t *testing.T) {
	password := []byte("test-password")
	salt := bytes.Repeat([]byte{0x42}, 16)
	const wantNormalHex = "337c613f12e5ded0b79572e3b6e022e4b0ec476226500075134bce41236daaf9"

	got := productionDeniabilityKey(password, salt)
	if gotHex := hex.EncodeToString(got); gotHex != wantNormalHex {
		t.Fatalf("deniability key drifted from frozen vector:\n got  = %s\n want = %s", gotHex, wantNormalHex)
	}
}
