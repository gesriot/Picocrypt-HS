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
		// fastDecode=true: this test covers framing + padding across the boundary
		// sizes (incl. 1 MiB), and parity-strip reconstructs UNDAMAGED data
		// identically to full decode while staying O(n). The full RS correction
		// path is covered (on bounded sizes) by the two tests below — full
		// Berlekamp-Welch on 1 MiB blocks is ~8192 decodes/size and times out slow
		// CI runners.
		dec, err := DecodeRSPayloadBlock(enc, rs, true, padded, false, true)
		if err != nil {
			t.Fatalf("decode n=%d: %v", n, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("roundtrip mismatch n=%d: got %d bytes want %d", n, len(dec), n)
		}
	}
}

// TestRSPayloadBlockFullDecodeRoundtrip exercises the full RS correction path
// (fastDecode=false) on UNDAMAGED data across partial/full-chunk boundaries,
// proving error correction reconstructs intact data and unpads the final chunk
// without falsely "correcting" good bytes. Sizes are kept small on purpose: full
// Berlekamp-Welch on a 1 MiB block is ~8192 decodes and is far too slow for CI;
// the framing/padding boundaries at 1 MiB are covered (fast) by the test above.
func TestRSPayloadBlockFullDecodeRoundtrip(t *testing.T) {
	rs := mustCodecs(t)
	sizes := []int{1, 127, 128, 129, 255, 256, 1000}
	for _, n := range sizes {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		enc, err := EncodeRSPayloadBlock(data, rs)
		if err != nil {
			t.Fatalf("encode n=%d: %v", n, err)
		}
		dec, err := DecodeRSPayloadBlock(enc, rs, true, false, false, false) // full correction
		if err != nil {
			t.Fatalf("full decode n=%d: %v", n, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("full-decode roundtrip mismatch n=%d: got %d bytes want %d", n, len(dec), n)
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
