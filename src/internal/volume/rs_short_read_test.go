package volume

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// shortReader caps every Read to at most max bytes before delegating to the
// underlying reader. It returns genuine short reads (n < len(p)) while still
// surfacing the underlying EOF, so the io.ReadFull loops in the encrypt and
// decrypt payload paths have to reassemble full blocks.
type shortReader struct {
	r   io.Reader
	max int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if len(p) > s.max {
		p = p[:s.max]
	}
	return s.r.Read(p)
}

// shortReadSeam installs newPayloadReader to wrap the payload reader in a
// shortReader, and returns a restore func. max is deliberately smaller than
// both 1 MiB and rsEncodedBlockSize so reads never align to RS block
// boundaries.
func shortReadSeam(max int) func() {
	prev := newPayloadReader
	newPayloadReader = func(r io.Reader) io.Reader {
		return &shortReader{r: r, max: max}
	}
	return func() { newPayloadReader = prev }
}

const shortReadMax = 100 * 1024 // < 1 MiB and < rsEncodedBlockSize

func newRSCodecsT(t *testing.T) *encoding.RSCodecs {
	t.Helper()
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	return rs
}

func randomPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// TestDecryptShortReadsRSBlockAligned covers the decrypt pass loop
// (decryptPayloadWithFastDecode). The volume is written with full reads (identity
// seam); decryption then runs under a short-read seam. With a bare fin.Read the
// loop hands a non-block-aligned chunk to decodeWithRSFast, mis-decoding the RS
// blocks and yielding ErrCorruptData / ErrAuthFailed. io.ReadFull reassembles
// full RS blocks regardless of read chunking.
func TestDecryptShortReadsRSBlockAligned(t *testing.T) {
	rs := newRSCodecsT(t)
	tmp := t.TempDir()

	plaintext := randomPlaintext(t, 2*1024*1024+12345) // >= 2 MiB, not block-aligned
	inputPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encPath := filepath.Join(tmp, "in.bin.pcv")
	decPath := filepath.Join(tmp, "out.bin")

	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encPath,
		Password:    "short-read-decrypt",
		ReedSolomon: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	restore := shortReadSeam(shortReadMax)
	defer restore()

	decReq := &DecryptRequest{
		InputFile:  encPath,
		OutputFile: decPath,
		Password:   "short-read-decrypt",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt under short-read seam: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted plaintext mismatch (len got=%d want=%d)", len(got), len(plaintext))
	}
}

// TestEncryptShortReadsRoundTrip covers the encrypt loop (encryptPayload).
// Encryption runs under a short-read seam; the resulting volume must decrypt
// cleanly under a normal (identity-seam) Decrypt. With a bare reader.Read the
// partial-block path in encodeWithRS pads a non-final block, so a normal decrypt
// cannot reproduce the plaintext.
func TestEncryptShortReadsRoundTrip(t *testing.T) {
	rs := newRSCodecsT(t)
	tmp := t.TempDir()

	plaintext := randomPlaintext(t, 2*1024*1024+9999) // >= 2 MiB
	inputPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encPath := filepath.Join(tmp, "in.bin.pcv")
	decPath := filepath.Join(tmp, "out.bin")

	restore := shortReadSeam(shortReadMax)
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encPath,
		Password:    "short-read-encrypt",
		ReedSolomon: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		restore()
		t.Fatalf("Encrypt under short-read seam: %v", err)
	}
	restore() // decrypt with identity (full reads)

	decReq := &DecryptRequest{
		InputFile:  encPath,
		OutputFile: decPath,
		Password:   "short-read-encrypt",
		Reporter:   &GoldenTestReporter{},
		RSCodecs:   rs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt (normal) of short-read-encrypted volume: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip plaintext mismatch (len got=%d want=%d)", len(got), len(plaintext))
	}
}

// TestVerifyFirstShortReadsRSBlockAligned covers the verify-first loop
// (decryptVerifyMACFirstWithDecode). The volume is written with full reads;
// Decrypt runs with VerifyFirst:true under a short-read seam. With a bare
// fin.Read the verify pass MACs non-block-aligned RS chunks, producing a false
// ErrAuthFailed.
func TestVerifyFirstShortReadsRSBlockAligned(t *testing.T) {
	rs := newRSCodecsT(t)
	tmp := t.TempDir()

	plaintext := randomPlaintext(t, 2*1024*1024+4242) // >= 2 MiB
	inputPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	encPath := filepath.Join(tmp, "in.bin.pcv")
	decPath := filepath.Join(tmp, "out.bin")

	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  encPath,
		Password:    "short-read-verifyfirst",
		ReedSolomon: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	restore := shortReadSeam(shortReadMax)
	defer restore()

	decReq := &DecryptRequest{
		InputFile:   encPath,
		OutputFile:  decPath,
		Password:    "short-read-verifyfirst",
		VerifyFirst: true,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rs,
	}
	if err := Decrypt(context.Background(), decReq); err != nil {
		t.Fatalf("Decrypt VerifyFirst under short-read seam: %v", err)
	}

	got, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("verify-first decrypted plaintext mismatch (len got=%d want=%d)", len(got), len(plaintext))
	}
}
