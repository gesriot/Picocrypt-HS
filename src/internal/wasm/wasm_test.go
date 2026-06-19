package wasm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
)

func TestDecryptV1(t *testing.T) {
	// Read the v1 test volume (password-only, no keyfiles)
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v1.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	// Decrypt with password "test"
	res, errCode := DecryptVolume(volumeData, []byte("test"), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	// Read expected content
	expected, err := os.ReadFile("../../testdata/golden/pico_test.txt")
	if err != nil {
		t.Fatalf("failed to read expected file: %v", err)
	}

	// Normalize line endings: git may convert \n → \r\n on Windows checkout
	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(res.Plaintext, expected) {
		t.Errorf("decrypted content doesn't match expected\ngot: %q\nwant: %q", res.Plaintext, expected)
	}
}

func TestDecryptV2(t *testing.T) {
	// Read the v2 test volume (password-only, no keyfiles)
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v2.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	// Decrypt with password "test"
	res, errCode := DecryptVolume(volumeData, []byte("test"), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	// Read expected content
	expected, err := os.ReadFile("../../testdata/golden/pico_test.txt")
	if err != nil {
		t.Fatalf("failed to read expected file: %v", err)
	}

	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(res.Plaintext, expected) {
		t.Errorf("decrypted content doesn't match expected\ngot: %q\nwant: %q", res.Plaintext, expected)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	volumeData, err := os.ReadFile("../../testdata/golden/pico_test_v2.txt.pcv")
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	_, errCode := DecryptVolume(volumeData, []byte("wrongpassword"), DecryptOptions{})
	if errCode != ErrWrongPassword {
		t.Errorf("expected error code %d, got %d", ErrWrongPassword, errCode)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	original := []byte("Hello, Picocrypt-NG WASM world!")
	password := "testpassword123"

	// Encrypt
	ciphertext, errCode := EncryptVolume(original, []byte(password), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}

	// Decrypt
	res, errCode := DecryptVolume(ciphertext, []byte(password), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	if !bytes.Equal(res.Plaintext, original) {
		t.Errorf("roundtrip failed\ngot: %q\nwant: %q", res.Plaintext, original)
	}
}

func TestEncryptDecryptLargerFile(t *testing.T) {
	// Create a larger test file (100KB)
	original := make([]byte, 100*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}
	password := "testpassword123"

	// Encrypt
	ciphertext, errCode := EncryptVolume(original, []byte(password), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("encrypt failed with error code %d", errCode)
	}

	// Decrypt
	res, errCode := DecryptVolume(ciphertext, []byte(password), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("decrypt failed with error code %d", errCode)
	}

	if !bytes.Equal(res.Plaintext, original) {
		t.Errorf("roundtrip failed for larger file")
	}
}

func TestWASMUsesWriteAuthValues(t *testing.T) {
	originalWriteAuthValues := writeAuthValues
	defer func() {
		writeAuthValues = originalWriteAuthValues
	}()

	sentinelKeyHash := bytes.Repeat([]byte{0xA1}, header.KeyHashSize)
	sentinelKeyfileHash := bytes.Repeat([]byte{0xB2}, header.KeyfileHashSize)
	sentinelAuthTag := bytes.Repeat([]byte{0xC3}, header.AuthTagSize)
	var calls int

	writeAuthValues = func(w io.WriterAt, offset int64, keyHash, keyfileHash, authTag []byte, rs *encoding.RSCodecs) error {
		calls++
		if offset != header.AuthValuesOffset(0) {
			t.Errorf("auth values offset = %d; want %d", offset, header.AuthValuesOffset(0))
		}
		if len(keyHash) != header.KeyHashSize {
			t.Errorf("keyHash size = %d; want %d", len(keyHash), header.KeyHashSize)
		}
		if len(keyfileHash) != header.KeyfileHashSize {
			t.Errorf("keyfileHash size = %d; want %d", len(keyfileHash), header.KeyfileHashSize)
		}
		if len(authTag) != header.AuthTagSize {
			t.Errorf("authTag size = %d; want %d", len(authTag), header.AuthTagSize)
		}

		return originalWriteAuthValues(w, offset, sentinelKeyHash, sentinelKeyfileHash, sentinelAuthTag, rs)
	}

	volumeData, errCode := EncryptVolume([]byte("phase 6 wasm auth writer guard"), []byte("phase6-password"), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}
	if calls != 1 {
		t.Fatalf("writeAuthValues calls = %d; want 1", calls)
	}

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}
	result, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if !bytes.Equal(result.Header.KeyHash, sentinelKeyHash) {
		t.Fatal("WASM header key hash was not written by writeAuthValues")
	}
	if !bytes.Equal(result.Header.KeyfileHash, sentinelKeyfileHash) {
		t.Fatal("WASM header keyfile hash was not written by writeAuthValues")
	}
	if !bytes.Equal(result.Header.AuthTag, sentinelAuthTag) {
		t.Fatal("WASM header auth tag was not written by writeAuthValues")
	}
}

func TestWASMRoundtripDesktopDecrypt(t *testing.T) {
	original := []byte("Phase 6 WASM standard volume decrypts through the shared desktop volume path.")
	password := "phase6-desktop-interop"

	volumeData, errCode := EncryptVolume(original, []byte(password), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}

	tmpDir := t.TempDir()
	encryptedPath := filepath.Join(tmpDir, "wasm-output.pcv")
	decryptedPath := filepath.Join(tmpDir, "desktop-output.txt")
	if err := os.WriteFile(encryptedPath, volumeData, 0600); err != nil {
		t.Fatalf("write encrypted volume: %v", err)
	}

	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile:  encryptedPath,
		OutputFile: decryptedPath,
		Password:   []byte(password),
		RSCodecs:   rsCodecs,
	}); err != nil {
		t.Fatalf("volume.Decrypt failed: %v", err)
	}

	plaintext, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("read decrypted output: %v", err)
	}
	if !bytes.Equal(plaintext, original) {
		t.Fatalf("desktop decrypt output mismatch\ngot:  %q\nwant: %q", plaintext, original)
	}
}

func observeWASMZeroingForTest(observer func(wasmZeroingEvent)) func() {
	previous := wasmZeroingObserver
	wasmZeroingObserver = observer
	return func() {
		wasmZeroingObserver = previous
	}
}

func TestWASMBuffersZeroed(t *testing.T) {
	plaintext := []byte("Phase 6 zeroing coverage needs plaintext-derived ciphertext staging.")
	password := "phase6-zeroing-password"

	var events []wasmZeroingEvent
	restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) {
		events = append(events, event)
	})
	defer restore()

	volumeData, errCode := EncryptVolume(plaintext, []byte(password), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}
	if len(volumeData) == 0 {
		t.Fatal("EncryptVolume returned empty volume")
	}
	if bytes.Equal(volumeData, make([]byte, len(volumeData))) {
		t.Fatal("returned volume bytes were wiped before return")
	}

	// The plaintext argument is caller-owned at the internal package boundary.
	// Browser bridge input-copy zeroing is covered by the bridge task; this test
	// only observes encryption-local Go buffers that EncryptVolume owns.
	if !bytes.Equal(plaintext, []byte("Phase 6 zeroing coverage needs plaintext-derived ciphertext staging.")) {
		t.Fatal("EncryptVolume wiped caller-owned plaintext input")
	}

	want := map[wasmZeroingBufferKind]bool{
		wasmZeroingPasswordBytes:    true,
		wasmZeroingHeaderSubkey:     true,
		wasmZeroingMACSubkey:        true,
		wasmZeroingSerpentKey:       true,
		wasmZeroingCiphertextChunk:  true,
		wasmZeroingCiphertextBuffer: true,
		wasmZeroingKeyfileHash:      true,
		wasmZeroingHeaderKeyHash:    true,
		wasmZeroingAuthTag:          true,
		wasmZeroingHeaderBuffer:     true,
	}
	seen := make(map[wasmZeroingBufferKind]wasmZeroingEvent)
	for _, event := range events {
		if event.Len == 0 {
			t.Fatalf("%s zeroing event had empty buffer", event.Kind)
		}
		if !event.Zeroed {
			t.Fatalf("%s buffer was not zeroed after cleanup", event.Kind)
		}
		seen[event.Kind] = event
	}
	for kind := range want {
		if _, ok := seen[kind]; !ok {
			t.Fatalf("missing zeroing event for %s; saw %v", kind, seen)
		}
	}

	for _, kind := range []wasmZeroingBufferKind{
		wasmZeroingPasswordBytes,
		wasmZeroingHeaderSubkey,
		wasmZeroingMACSubkey,
		wasmZeroingSerpentKey,
		wasmZeroingCiphertextChunk,
		wasmZeroingCiphertextBuffer,
		wasmZeroingHeaderKeyHash,
		wasmZeroingAuthTag,
		wasmZeroingHeaderBuffer,
	} {
		if !seen[kind].WasNonZero {
			t.Fatalf("%s buffer was already zero before cleanup; test would be vacuous", kind)
		}
	}
}

func TestWASMUnsupportedFeatureFlagsReturnUnsupported(t *testing.T) {
	cases := []struct {
		name  string
		flags header.Flags
	}{
		{
			name:  "reed_solomon_payload",
			flags: header.Flags{ReedSolomon: true},
		},
		{
			name:  "reed_solomon_padding",
			flags: header.Flags{Padded: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			volumeData := wasmVolumeWithFlags(t, tc.flags)

			_, errCode := DecryptVolume(volumeData, []byte("phase6-unsupported-flags"), DecryptOptions{})
			if errCode != ErrUnsupported {
				t.Fatalf("DecryptVolume error code = %d; want ErrUnsupported", errCode)
			}
		})
	}
}

func TestWASMDecryptBuffersZeroed(t *testing.T) {
	original := []byte("Phase 6 decrypt zeroing coverage needs returned plaintext intact.")
	password := "phase6-decrypt-zeroing"
	volumeData, errCode := EncryptVolume(original, []byte(password), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}

	var events []wasmZeroingEvent
	restore := observeWASMZeroingForTest(func(event wasmZeroingEvent) {
		events = append(events, event)
	})
	defer restore()

	res, errCode := DecryptVolume(volumeData, []byte(password), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("DecryptVolume returned error code %d", errCode)
	}
	plaintext := res.Plaintext
	if !bytes.Equal(plaintext, original) {
		t.Fatalf("plaintext mismatch\ngot:  %q\nwant: %q", plaintext, original)
	}
	if bytes.Equal(plaintext, make([]byte, len(plaintext))) {
		t.Fatal("returned plaintext was wiped before return")
	}

	// This observes package-owned Go slices only. JavaScript engine copies and
	// Go runtime/GC-managed copies cannot be inspected directly from this test.
	want := map[wasmZeroingBufferKind]bool{
		wasmZeroingDecryptPasswordBytes:  true,
		wasmZeroingDecryptKeyfileHash:    false,
		wasmZeroingDecryptHeaderSubkey:   true,
		wasmZeroingDecryptMACSubkey:      true,
		wasmZeroingDecryptSerpentKey:     true,
		wasmZeroingDecryptPlaintextChunk: true,
		wasmZeroingDecryptComputedMAC:    true,
	}
	seen := make(map[wasmZeroingBufferKind]wasmZeroingEvent)
	for _, event := range events {
		if event.Len == 0 {
			t.Fatalf("%s zeroing event had empty buffer", event.Kind)
		}
		if !event.Zeroed {
			t.Fatalf("%s buffer was not zeroed after cleanup", event.Kind)
		}
		seen[event.Kind] = event
	}
	for kind, mustBeNonZero := range want {
		event, ok := seen[kind]
		if !ok {
			t.Fatalf("missing zeroing event for %s; saw %v", kind, seen)
		}
		if mustBeNonZero && !event.WasNonZero {
			t.Fatalf("%s buffer was already zero before cleanup; test would be vacuous", kind)
		}
	}
}

func TestWASMParanoidCommentsDesktopDecrypt(t *testing.T) {
	original := []byte("P0: paranoid + comments interop through the desktop volume path.")
	password := "p0-paranoid-interop"
	comments := "made in the browser"

	volumeData, errCode := EncryptVolume(original, []byte(password), EncryptOptions{Paranoid: true, Comments: comments})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}

	// Header must record paranoid + the plaintext comments.
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}
	res, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if !res.Header.Flags.Paranoid {
		t.Fatal("paranoid flag not set in WASM-produced header")
	}
	if res.Header.Comments != comments {
		t.Fatalf("header comments = %q; want %q", res.Header.Comments, comments)
	}

	// Desktop must decrypt the WASM paranoid volume to identical plaintext.
	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "wasm.pcv")
	decPath := filepath.Join(tmpDir, "desktop.txt")
	if err := os.WriteFile(encPath, volumeData, 0600); err != nil {
		t.Fatalf("write volume: %v", err)
	}
	if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
		InputFile:  encPath,
		OutputFile: decPath,
		Password:   []byte(password),
		RSCodecs:   rs,
	}); err != nil {
		t.Fatalf("volume.Decrypt failed: %v", err)
	}
	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("desktop decrypt mismatch\ngot:  %q\nwant: %q", got, original)
	}
}

func TestWASMDecryptParanoidAndComments(t *testing.T) {
	original := []byte("P0: desktop paranoid volume decrypts in WASM and yields comments.")
	password := "p0-desktop-to-wasm"
	comments := "round-trip comment"

	// Desktop-encrypt a paranoid volume with comments to a temp file.
	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "plain.txt")
	outPath := filepath.Join(tmpDir, "vol.pcv")
	if err := os.WriteFile(inPath, original, 0600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}
	if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{
		InputFile:  inPath,
		OutputFile: outPath,
		Password:   []byte(password),
		Paranoid:   true,
		Comments:   comments,
		RSCodecs:   rs,
	}); err != nil {
		t.Fatalf("volume.Encrypt failed: %v", err)
	}
	volumeData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read volume: %v", err)
	}

	got, errCode := DecryptVolume(volumeData, []byte(password), DecryptOptions{})
	if errCode != 0 {
		t.Fatalf("DecryptVolume error code %d", errCode)
	}
	if !bytes.Equal(got.Plaintext, original) {
		t.Fatalf("plaintext mismatch\ngot:  %q\nwant: %q", got.Plaintext, original)
	}
	if got.Comments != comments {
		t.Fatalf("comments = %q; want %q", got.Comments, comments)
	}
}

func TestWASMKeyfileEncryptDesktopDecrypt(t *testing.T) {
	kfA := []byte("keyfile-one-contents")
	kfB := []byte("keyfile-two-contents-longer")
	original := []byte("P1: WASM keyfile volume decrypts on desktop.")
	password := "p1-keyfile-interop"

	for _, ordered := range []bool{true, false} {
		t.Run(fmt.Sprintf("ordered=%v", ordered), func(t *testing.T) {
			volumeData, errCode := EncryptVolume(original, []byte(password), EncryptOptions{
				Keyfiles:       [][]byte{kfA, kfB},
				KeyfileOrdered: ordered,
			})
			if errCode != 0 {
				t.Fatalf("EncryptVolume error code %d", errCode)
			}

			// Header records the keyfile flags.
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			res, err := header.NewReader(bytes.NewReader(volumeData), rs).ReadHeader()
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			if !res.Header.Flags.UseKeyfiles || res.Header.Flags.KeyfileOrdered != ordered {
				t.Fatalf("keyfile flags wrong: use=%v ordered=%v", res.Header.Flags.UseKeyfiles, res.Header.Flags.KeyfileOrdered)
			}

			// Desktop decrypts with the same keyfiles (written to temp files).
			tmp := t.TempDir()
			encPath := filepath.Join(tmp, "v.pcv")
			decPath := filepath.Join(tmp, "out.txt")
			kaPath := filepath.Join(tmp, "a.key")
			kbPath := filepath.Join(tmp, "b.key")
			for p, c := range map[string][]byte{encPath: volumeData, kaPath: kfA, kbPath: kfB} {
				if err := os.WriteFile(p, c, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := volume.Decrypt(context.Background(), &volume.DecryptRequest{
				InputFile: encPath, OutputFile: decPath,
				Password: []byte(password), Keyfiles: []string{kaPath, kbPath},
				RSCodecs: rs,
			}); err != nil {
				t.Fatalf("volume.Decrypt: %v", err)
			}
			got, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, original) {
				t.Fatalf("desktop decrypt mismatch")
			}
		})
	}
}

func TestWASMDecryptKeyfiles(t *testing.T) {
	kfA := []byte("kf-alpha")
	kfB := []byte("kf-beta-content")
	original := []byte("P1: desktop keyfile volume decrypts in WASM.")
	password := "p1-desktop-keyfiles"

	for _, ordered := range []bool{true, false} {
		t.Run(fmt.Sprintf("ordered=%v", ordered), func(t *testing.T) {
			tmp := t.TempDir()
			inPath := filepath.Join(tmp, "p.txt")
			outPath := filepath.Join(tmp, "v.pcv")
			kaPath := filepath.Join(tmp, "a.key")
			kbPath := filepath.Join(tmp, "b.key")
			for p, c := range map[string][]byte{inPath: original, kaPath: kfA, kbPath: kfB} {
				if err := os.WriteFile(p, c, 0600); err != nil {
					t.Fatal(err)
				}
			}
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			if err := volume.Encrypt(context.Background(), &volume.EncryptRequest{
				InputFile: inPath, OutputFile: outPath,
				Password: []byte(password), Keyfiles: []string{kaPath, kbPath}, KeyfileOrdered: ordered,
				RSCodecs: rs,
			}); err != nil {
				t.Fatalf("volume.Encrypt: %v", err)
			}
			volumeData, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}

			// Correct keyfiles → success.
			got, code := DecryptVolume(volumeData, []byte(password), DecryptOptions{Keyfiles: [][]byte{kfA, kfB}})
			if code != 0 {
				t.Fatalf("decrypt code %d; want 0", code)
			}
			if !bytes.Equal(got.Plaintext, original) {
				t.Fatalf("plaintext mismatch")
			}

			// Missing keyfiles → ErrKeyfilesRequired.
			if _, code := DecryptVolume(volumeData, []byte(password), DecryptOptions{}); code != ErrKeyfilesRequired {
				t.Fatalf("missing keyfiles code %d; want %d", code, ErrKeyfilesRequired)
			}
			// Wrong keyfiles → ErrKeyfilesIncorrect.
			if _, code := DecryptVolume(volumeData, []byte(password), DecryptOptions{Keyfiles: [][]byte{[]byte("wrong")}}); code != ErrKeyfilesIncorrect {
				t.Fatalf("wrong keyfiles code %d; want %d", code, ErrKeyfilesIncorrect)
			}
		})
	}
}

func TestWASMDecryptV1KeyfilesRejected(t *testing.T) {
	v1, err := os.ReadFile("../../testdata/golden/pico_test_v1.txt.pcv")
	if err != nil {
		t.Fatalf("read v1 golden: %v", err)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	kfFlags := header.Flags{UseKeyfiles: true}
	flagsEnc, err := encoding.Encode(rs.RS5, kfFlags.ToBytes())
	if err != nil {
		t.Fatalf("encode flags: %v", err)
	}
	patched := append([]byte(nil), v1...)
	off := header.VersionEncSize + header.CommentLenEncSize
	copy(patched[off:off+header.FlagsEncSize], flagsEnc)

	_, code := DecryptVolume(patched, []byte("test"), DecryptOptions{Keyfiles: [][]byte{[]byte("kf")}})
	if code != ErrUnsupported {
		t.Fatalf("v1+keyfiles code=%d; want ErrUnsupported (%d) — must fail closed, not decrypt wrong", code, ErrUnsupported)
	}
}

func TestWASMKeyfileBuffersZeroed(t *testing.T) {
	// Use large, content-rich keyfiles so the XOR cipher key is astronomically
	// unlikely to be all-zero (passwordKey == keyfileKey collision).
	kfA := bytes.Repeat([]byte("keyfile-zeroing-alpha-sentinel-"), 10)
	kfB := bytes.Repeat([]byte("keyfile-zeroing-beta-sentinel--"), 10)
	original := []byte("keyfile zeroing observer coverage")
	password := "kf-zeroing-password-distinct"

	// --- Encrypt with keyfiles under the zeroing observer ---
	var encEvents []wasmZeroingEvent
	restoreEnc := observeWASMZeroingForTest(func(e wasmZeroingEvent) {
		encEvents = append(encEvents, e)
	})
	volumeData, errCode := EncryptVolume(original, []byte(password), EncryptOptions{
		Keyfiles: [][]byte{kfA, kfB},
	})
	restoreEnc()
	if errCode != 0 {
		t.Fatalf("EncryptVolume error code %d", errCode)
	}

	// All three secrets must end up zeroed.
	encZeroed := []wasmZeroingBufferKind{
		wasmZeroingKeyfileKey,
		wasmZeroingCipherKey,
		wasmZeroingKeyfileHash,
	}
	// keyfileKey and keyfileHash are wiped solely by our observed defers, so they
	// must have been non-zero when observed (vacuity guard). cipherKey is ALSO
	// wiped by CipherSuite.Close() (it aliases cs.key), which is registered later
	// and so runs first in LIFO order — by the time our defensive observer runs,
	// cipherKey is already zero. WasNonZero is legitimately false for it.
	encNonZero := []wasmZeroingBufferKind{
		wasmZeroingKeyfileKey,
		wasmZeroingKeyfileHash,
	}
	encSeen := make(map[wasmZeroingBufferKind]wasmZeroingEvent)
	for _, e := range encEvents {
		encSeen[e.Kind] = e
	}
	for _, kind := range encZeroed {
		e, ok := encSeen[kind]
		if !ok {
			t.Fatalf("encrypt: missing zeroing event for %s; saw %v", kind, encSeen)
		}
		if !e.Zeroed {
			t.Fatalf("encrypt: %s not zeroed after cleanup", kind)
		}
	}
	for _, kind := range encNonZero {
		if !encSeen[kind].WasNonZero {
			t.Fatalf("encrypt: %s was already zero before cleanup; test would be vacuous", kind)
		}
	}

	// --- Decrypt with keyfiles under the zeroing observer ---
	var decEvents []wasmZeroingEvent
	restoreDec := observeWASMZeroingForTest(func(e wasmZeroingEvent) {
		decEvents = append(decEvents, e)
	})
	res, errCode := DecryptVolume(volumeData, []byte(password), DecryptOptions{
		Keyfiles: [][]byte{kfA, kfB},
	})
	restoreDec()
	if errCode != 0 {
		t.Fatalf("DecryptVolume error code %d", errCode)
	}
	if !bytes.Equal(res.Plaintext, original) {
		t.Fatalf("plaintext mismatch after keyfile decrypt")
	}

	decZeroed := []wasmZeroingBufferKind{
		wasmZeroingDecryptKeyfileKey,
		wasmZeroingDecryptCipherKey,
		wasmZeroingDecryptKeyfileHash,
	}
	// As on encrypt: cipherKey is wiped by CipherSuite.Close() first (LIFO), so its
	// WasNonZero is legitimately false; the vacuity guard rides on keyfileKey and
	// keyfileHash, which only our observed defers touch.
	decNonZero := []wasmZeroingBufferKind{
		wasmZeroingDecryptKeyfileKey,
		wasmZeroingDecryptKeyfileHash,
	}
	decSeen := make(map[wasmZeroingBufferKind]wasmZeroingEvent)
	for _, e := range decEvents {
		decSeen[e.Kind] = e
	}
	for _, kind := range decZeroed {
		e, ok := decSeen[kind]
		if !ok {
			t.Fatalf("decrypt: missing zeroing event for %s; saw %v", kind, decSeen)
		}
		if !e.Zeroed {
			t.Fatalf("decrypt: %s not zeroed after cleanup", kind)
		}
	}
	for _, kind := range decNonZero {
		if !decSeen[kind].WasNonZero {
			t.Fatalf("decrypt: %s was already zero before cleanup; test would be vacuous", kind)
		}
	}
}

func wasmVolumeWithFlags(t *testing.T, flags header.Flags) []byte {
	t.Helper()

	volumeData, errCode := EncryptVolume([]byte("unsupported wasm feature flags"), []byte("phase6-unsupported-flags"), EncryptOptions{})
	if errCode != 0 {
		t.Fatalf("EncryptVolume returned error code %d", errCode)
	}

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}
	flagsEnc, err := encoding.Encode(rs.RS5, flags.ToBytes())
	if err != nil {
		t.Fatalf("encode flags: %v", err)
	}

	patched := append([]byte(nil), volumeData...)
	flagsOffset := header.VersionEncSize + header.CommentLenEncSize
	copy(patched[flagsOffset:flagsOffset+header.FlagsEncSize], flagsEnc)
	return patched
}
