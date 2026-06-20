package encoding

import (
	"bytes"
	"errors"
	"testing"
)

func mustCodecs(t *testing.T) *RSCodecs {
	t.Helper()
	rs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	return rs
}

func TestRSPayloadBlockRoundtrip(t *testing.T) {
	rs := mustCodecs(t)
	const miB = 1 << 20
	sizes := []int{1, 127, 128, 129, 255, miB - 129, miB - 128, miB - 1, miB}
	for _, n := range sizes {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		enc, err := EncodeRSPayloadBlock(data, rs)
		if err != nil {
			t.Fatalf("encode n=%d: %v", n, err)
		}
		// Desktop convention: a partial block whose padded chunks reach 8192 fills a
		// full RSEncodedBlockSize; the caller signals that via the Padded flag.
		padded := n < miB && len(enc) == RSEncodedBlockSize
		dec, err := DecodeRSPayloadBlock(enc, rs, true, padded, false, false)
		if err != nil {
			t.Fatalf("decode n=%d: %v", n, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("roundtrip mismatch n=%d: got %d bytes want %d", n, len(dec), n)
		}
	}
}

func TestRSPayloadBlockRepairsCorrectableErrors(t *testing.T) {
	rs := mustCodecs(t)
	data := make([]byte, 256) // two full 128-byte chunks
	for i := range data {
		data[i] = byte(i)
	}
	enc, err := EncodeRSPayloadBlock(data, rs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Flip 4 bytes in the first 136-byte chunk's data region (RS128 corrects <=4).
	for i := 0; i < 4; i++ {
		enc[i] ^= 0xFF
	}
	dec, err := DecodeRSPayloadBlock(enc, rs, true, false, false, false) // full correction
	if err != nil {
		t.Fatalf("full decode of correctable damage failed: %v", err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatal("full RS decode did not repair correctable damage")
	}
}

func TestRSPayloadBlockUncorrectableReturnsErrCorruptData(t *testing.T) {
	rs := mustCodecs(t)
	data := make([]byte, 256)
	enc, err := EncodeRSPayloadBlock(data, rs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i := 0; i < 9; i++ { // > 4 errors in one chunk: beyond RS budget
		enc[i] ^= 0xFF
	}
	_, err = DecodeRSPayloadBlock(enc, rs, true, false, false, false)
	if !errors.Is(err, ErrCorruptData) {
		t.Fatalf("want ErrCorruptData, got %v", err)
	}
}
