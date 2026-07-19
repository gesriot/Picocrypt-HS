package fileops

import (
	"bytes"
	"io"
	"testing"
)

// eofDataReader returns its entire payload together with io.EOF in a single Read,
// then io.EOF with no data on every subsequent Read. This is a legal io.Reader
// (Go permits returning n>0 alongside io.EOF) and exercises the encryptedReader
// path where data arrives simultaneously with EOF.
type eofDataReader struct {
	data []byte
	done bool
}

func (e *eofDataReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.EOF
	}
	n := copy(p, e.data)
	e.done = true
	return n, io.EOF
}

// TestEncryptedReaderDecryptsDataDeliveredWithEOF: a reader that returns data
// together with io.EOF must still be decrypted. The old `err == nil && n > 0`
// guard skipped XORKeyStream when err == io.EOF, leaking raw ciphertext to the
// caller.
func TestEncryptedReaderDecryptsDataDeliveredWithEOF(t *testing.T) {
	c, err := NewTempZipCiphers()
	if err != nil {
		t.Fatalf("NewTempZipCiphers: %v", err)
	}
	defer c.Close()

	plaintext := []byte("Picocrypt-NG encryptedReader EOF+data regression payload.")

	// Encrypt the known plaintext with the Writer cipher to obtain ciphertext.
	ciphertext := make([]byte, len(plaintext))
	c.Writer.XORKeyStream(ciphertext, plaintext)

	er := &encryptedReader{r: &eofDataReader{data: ciphertext}, cipher: c.Reader}
	got, err := io.ReadAll(er)
	if err != nil {
		t.Fatalf("io.ReadAll(encryptedReader): %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("encryptedReader did not decrypt data delivered with io.EOF\n got: %q\nwant: %q", got, plaintext)
	}
}
