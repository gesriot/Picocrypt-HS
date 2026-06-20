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
