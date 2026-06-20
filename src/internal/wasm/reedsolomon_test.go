package wasm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
)

// desktopDecrypt decrypts a WASM-produced volume via the shared desktop engine,
// proving the on-disk RS framing is byte-compatible.
func desktopDecrypt(t *testing.T, volumeData []byte, password string) []byte {
	t.Helper()
	tmp := t.TempDir()
	in := filepath.Join(tmp, "v.pcv")
	out := filepath.Join(tmp, "v.out")
	if err := os.WriteFile(in, volumeData, 0600); err != nil {
		t.Fatalf("write volume: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(password), RSCodecs: rs,
	}); err != nil {
		t.Fatalf("desktop Decrypt: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return got
}

func TestWASMReedSolomonEncryptDesktopDecrypt(t *testing.T) {
	const miB = 1 << 20
	password := "rs-encrypt-interop"
	sizes := []int{1, 200, miB - 129, miB - 128, miB - 1, miB, miB + 17, 2*miB - 1}
	for _, n := range sizes {
		plaintext := make([]byte, n)
		for i := range plaintext {
			plaintext[i] = byte(i*13 + 1)
		}
		vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
		if code != 0 {
			t.Fatalf("n=%d EncryptVolume code %d", n, code)
		}
		// Header must advertise RS; Padded iff the final partial block fills a full block.
		hdr := readHeaderForTest(t, vol)
		if !hdr.Flags.ReedSolomon {
			t.Fatalf("n=%d: ReedSolomon flag not set", n)
		}
		wantPadded := n%miB >= miB-128
		if hdr.Flags.Padded != wantPadded {
			t.Fatalf("n=%d: Padded=%v want %v", n, hdr.Flags.Padded, wantPadded)
		}
		got := desktopDecrypt(t, vol, password)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("n=%d: desktop decrypt mismatch (%d vs %d bytes)", n, len(got), n)
		}
	}
}

func readHeaderForTest(t *testing.T, volumeData []byte) *header.VolumeHeader {
	t.Helper()
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	res, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	return res.Header
}

func TestWASMReedSolomonRoundtrip(t *testing.T) {
	const miB = 1 << 20
	password := "rs-roundtrip"
	for _, n := range []int{1, 200, miB - 128, miB - 1, miB, miB + 5, 2 * miB} {
		plaintext := make([]byte, n)
		for i := range plaintext {
			plaintext[i] = byte(i*5 + 9)
		}
		vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
		if code != 0 {
			t.Fatalf("n=%d encrypt code %d", n, code)
		}
		res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
		if code != 0 {
			t.Fatalf("n=%d decrypt code %d", n, code)
		}
		if !bytes.Equal(res.Plaintext, plaintext) {
			t.Fatalf("n=%d roundtrip mismatch", n)
		}
	}
}

func TestWASMReedSolomonRepairsCorrectableDamage(t *testing.T) {
	password := "rs-repair"
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	// Corrupt 4 bytes inside the first payload chunk's DATA region (first 128 of the
	// first 136-byte block) so the fast pass yields a wrong MAC and the full-RS retry
	// must repair it. RS128 corrects up to 4 errors per 136-byte block.
	payloadStart := header.HeaderSize(0)
	for i := 0; i < 4; i++ {
		vol[payloadStart+i] ^= 0xFF
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("expected repair, got code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("repaired plaintext mismatch")
	}
}

func TestWASMReedSolomonUncorrectableFailsClosed(t *testing.T) {
	password := "rs-uncorrectable"
	plaintext := make([]byte, 4096)
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	// 9 byte-errors in one 136-byte block: beyond the RS budget -> unrecoverable.
	payloadStart := header.HeaderSize(0)
	for i := 0; i < 9; i++ {
		vol[payloadStart+i] ^= 0xFF
	}
	_, code = DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != ErrModifiedData {
		t.Fatalf("want ErrModifiedData(%d), got %d", ErrModifiedData, code)
	}
}

func TestWASMReedSolomonDesktopEncryptWASMDecrypt(t *testing.T) {
	password := "desktop-rs-to-wasm"
	plaintext := []byte("Desktop-encrypted RS volume must decrypt in WASM unchanged.")
	tmp := t.TempDir()
	in := filepath.Join(tmp, "p.txt")
	out := filepath.Join(tmp, "p.pcv")
	if err := os.WriteFile(in, plaintext, 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{
		InputFile: in, OutputFile: out, Password: []byte(password),
		ReedSolomon: true, RSCodecs: rs,
	}); err != nil {
		t.Fatalf("desktop Encrypt: %v", err)
	}
	vol, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read volume: %v", err)
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("WASM decrypt code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("desktop->WASM RS decrypt mismatch")
	}
}

func TestWASMReedSolomonParanoidRoundtrip(t *testing.T) {
	password := "rs-paranoid"
	plaintext := make([]byte, 5000)
	for i := range plaintext {
		plaintext[i] = byte(i * 3)
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true, Paranoid: true})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{})
	if code != 0 {
		t.Fatalf("decrypt code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("paranoid RS roundtrip mismatch")
	}
}

func TestWASMReedSolomonWithKeyfiles(t *testing.T) {
	password := "rs-keyfiles"
	kf := [][]byte{[]byte("keyfile-alpha-contents"), []byte("keyfile-beta-contents")}
	plaintext := make([]byte, 3000)
	for i := range plaintext {
		plaintext[i] = byte(i + 7)
	}
	clone := func(in [][]byte) [][]byte {
		out := make([][]byte, len(in))
		for i, b := range in {
			out[i] = append([]byte(nil), b...)
		}
		return out
	}
	vol, code := EncryptVolume(plaintext, []byte(password), EncryptOptions{ReedSolomon: true, Keyfiles: clone(kf)})
	if code != 0 {
		t.Fatalf("encrypt code %d", code)
	}
	res, code := DecryptVolume(vol, []byte(password), DecryptOptions{Keyfiles: clone(kf)})
	if code != 0 {
		t.Fatalf("decrypt code %d", code)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatal("RS+keyfiles roundtrip mismatch")
	}
}
