package volume

import (
	"bytes"
	"encoding/hex"
	"testing"

	"Picocrypt-NG/internal/crypto"
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

	// Frozen golden anchors for the production Argon2id parameters, pinned to the
	// fixed password+salt above. These are INDEPENDENT of the crypto.Argon2* consts:
	// any parameter regression (e.g. Argon2NormalPasses 4->3) makes the wrapper output
	// drift away from these literals and turns the test red. CRITICAL: changing these
	// constants breaks decryption of every existing 2.08/2.09 volume.
	// Normal params: passes=4, memory=1<<20, threads=4, keylen=32.
	const wantNormalHex = "337c613f12e5ded0b79572e3b6e022e4b0ec476226500075134bce41236daaf9"
	// Paranoid params: passes=8, memory=1<<20, threads=8, keylen=32.
	const wantParanoidHex = "30c552d4a4571dfab29e29fac304d5178116d45fc3129dfc3bfb070c25057d6f"

	gotNormal, err := deriveVolumeKey(password, salt, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(gotNormal); got != wantNormalHex {
		t.Fatalf("normal volume key drifted from frozen vector:\n got  = %s\n want = %s", got, wantNormalHex)
	}

	gotParanoid, err := deriveVolumeKey(password, salt, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(gotParanoid); got != wantParanoidHex {
		t.Fatalf("paranoid volume key drifted from frozen vector:\n got  = %s\n want = %s", got, wantParanoidHex)
	}

	// The deniability KDF uses the NORMAL Argon2 parameters, so on identical inputs it
	// must equal the normal-mode golden. This pins productionDeniabilityKey's consts.
	gotDeniability := deriveDeniabilityKey(password, salt)
	if got := hex.EncodeToString(gotDeniability); got != wantNormalHex {
		t.Fatalf("deniability key drifted from frozen vector:\n got  = %s\n want = %s", got, wantNormalHex)
	}
}
