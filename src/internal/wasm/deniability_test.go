package wasm

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WASM-produced deniable volume must (a) have no readable header and (b) be
// stripped by the REAL desktop deniability code, with the recovered inner .pcv
// decrypting back in WASM. This pins the outer-layer byte format against desktop.
func TestDeniabilityWrapDesktopUnwrap(t *testing.T) {
	original := []byte("P4: WASM-wrapped deniable volume, stripped by desktop.")
	password := []byte("p4-wrap-interop")

	vol, code := EncryptVolume(original, password, EncryptOptions{Deniability: true})
	if code != 0 {
		t.Fatalf("encrypt(deniability) code %d", code)
	}

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	// No readable header: the first 15 bytes must NOT decode to a VALID version.
	// (RS5 decode can "succeed" on random bytes by correcting to a non-version
	// codeword, so the MatchVersion check is required — mirrors volume.IsDeniable.)
	if vd, derr := encoding.Decode(rs.RS5, append([]byte(nil), vol[:15]...), false); derr == nil && header.MatchVersion(vd) {
		t.Fatal("deniable volume leaked a decodable version header (not deniable)")
	}

	tmp := t.TempDir()
	path := filepath.Join(tmp, "deniable.pcv")
	if err := os.WriteFile(path, vol, 0o600); err != nil {
		t.Fatalf("write deniable volume: %v", err)
	}
	if !volume.IsDeniable(path, rs) {
		t.Fatal("desktop did not recognize the WASM volume as deniable")
	}
	innerPath, err := volume.RemoveDeniability(path, password, nil, rs)
	if err != nil {
		t.Fatalf("desktop RemoveDeniability: %v", err)
	}
	innerBytes, err := os.ReadFile(innerPath)
	if err != nil {
		t.Fatalf("read inner: %v", err)
	}
	res, code := DecryptVolume(innerBytes, password, DecryptOptions{})
	if code != 0 {
		t.Fatalf("decrypt inner code %d", code)
	}
	if !bytes.Equal(res.Plaintext, original) {
		t.Fatalf("plaintext mismatch\ngot:  %q\nwant: %q", res.Plaintext, original)
	}
}

// isDeniable must be TRUE for a wrapped volume and FALSE for every normal volume
// variant (no false positives — a valid header decodes to a version immediately).
func TestIsDeniableDetection(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	pw := []byte("p4-detect")
	plain := []byte(strings.Repeat("detect-", 300))

	deniable, code := EncryptVolume(plain, pw, EncryptOptions{Deniability: true})
	if code != 0 {
		t.Fatalf("encrypt deniable code %d", code)
	}
	if !isDeniable(deniable, rs) {
		t.Fatal("wrapped volume must be detected as deniable")
	}

	regulars := map[string]EncryptOptions{
		"plain":    {},
		"paranoid": {Paranoid: true},
		"rs":       {ReedSolomon: true},
		"keyfiles": {Keyfiles: [][]byte{[]byte("kf-one"), []byte("kf-two-longer")}},
		"comments": {Comments: "a deniable-looking comment"},
	}
	for name, opts := range regulars {
		t.Run(name, func(t *testing.T) {
			vol, code := EncryptVolume(plain, pw, opts)
			if code != 0 {
				t.Fatalf("encrypt %s code %d", name, code)
			}
			if isDeniable(vol, rs) {
				t.Fatalf("regular %s volume misclassified as deniable", name)
			}
		})
	}

	// Too-short input cannot be deniable.
	if isDeniable([]byte("short"), rs) {
		t.Fatal("sub-minimum-size input must not be deniable")
	}
}
