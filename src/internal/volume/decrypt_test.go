package volume

import (
	"bytes"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
)

// buildEncodedMiB constructs one full-MiB RS128-encoded block deterministically
// via the post-RS-01 encoding.Encode(rs.RS128, ...) loop (two-return signature).
// The plaintext is a deterministic ramp so decoded output is non-trivial.
func buildEncodedMiB(t *testing.T, rs *encoding.RSCodecs) (plain, enc []byte) {
	t.Helper()
	plain = make([]byte, util.MiB)
	for i := range plain {
		plain[i] = byte(i)
	}
	for j := 0; j < util.MiB; j += encoding.RS128DataSize {
		e, err := encoding.Encode(rs.RS128, plain[j:j+encoding.RS128DataSize])
		if err != nil {
			t.Fatalf("Encode chunk at %d: %v", j, err)
		}
		enc = append(enc, e...)
	}
	return plain, enc
}

// buildEncodedChunks encodes nChunks worth of deterministic plaintext, where the
// final lastLen bytes (<= 128) are PKCS#7-padded into the last 136-byte block
// (mirrors the encode side for a partial trailing chunk). Returns the raw
// (unpadded) plaintext and the RS128-encoded bytes.
func buildEncodedChunks(t *testing.T, rs *encoding.RSCodecs, nFullChunks, lastLen int) (plain, enc []byte) {
	t.Helper()
	// Full chunks.
	for c := 0; c < nFullChunks; c++ {
		chunk := make([]byte, encoding.RS128DataSize)
		for i := range chunk {
			chunk[i] = byte(c*7 + i)
		}
		plain = append(plain, chunk...)
		e, err := encoding.Encode(rs.RS128, chunk)
		if err != nil {
			t.Fatalf("Encode full chunk %d: %v", c, err)
		}
		enc = append(enc, e...)
	}
	// Trailing partial chunk, padded to 128 before encoding (encode-side behavior).
	last := make([]byte, lastLen)
	for i := range last {
		last[i] = byte(0xA0 + i)
	}
	plain = append(plain, last...)
	e, err := encoding.Encode(rs.RS128, encoding.Pad(last))
	if err != nil {
		t.Fatalf("Encode padded last chunk: %v", err)
	}
	enc = append(enc, e...)
	return plain, enc
}

// expectedDecode reproduces decodeWithRSFast's append sequence using the per-chunk
// encoding.Decode loop, so the test compares the function against an independent
// reconstruction of the exact same bytes (the D-05 byte-identical guard).
func expectedDecode(t *testing.T, data []byte, rs *encoding.RSCodecs, isLast, padded, fastDecode bool) []byte {
	t.Helper()
	var result []byte
	fullBlockEncodedSize := util.MiB / encoding.RS128DataSize * encoding.RS128EncodedSize

	if len(data) == fullBlockEncodedSize {
		for i := 0; i < fullBlockEncodedSize; i += encoding.RS128EncodedSize {
			decoded, err := encoding.Decode(rs.RS128, data[i:i+encoding.RS128EncodedSize], fastDecode)
			if err != nil {
				t.Fatalf("expected Decode (full) at %d: %v", i, err)
			}
			if isLast && i == fullBlockEncodedSize-encoding.RS128EncodedSize && padded {
				decoded = encoding.Unpad(decoded)
			}
			result = append(result, decoded...)
		}
		return result
	}

	chunks := len(data)/encoding.RS128EncodedSize - 1
	for i := 0; i < chunks; i++ {
		decoded, err := encoding.Decode(rs.RS128, data[i*encoding.RS128EncodedSize:(i+1)*encoding.RS128EncodedSize], fastDecode)
		if err != nil {
			t.Fatalf("expected Decode (partial) at chunk %d: %v", i, err)
		}
		result = append(result, decoded...)
	}
	lastChunkStart := chunks * encoding.RS128EncodedSize
	lastChunkEnd := lastChunkStart + encoding.RS128EncodedSize
	if lastChunkEnd > len(data) {
		lastChunkEnd = len(data)
	}
	decoded, err := encoding.Decode(rs.RS128, data[lastChunkStart:lastChunkEnd], fastDecode)
	if err != nil {
		t.Fatalf("expected Decode (last) at %d: %v", lastChunkStart, err)
	}
	result = append(result, encoding.Unpad(decoded)...)
	return result
}

// TestDecodeWithRSFast asserts decodeWithRSFast output is byte-identical to an
// independent per-chunk encoding.Decode reconstruction across the full-MiB,
// partial, and padded-last-chunk branches in both fast and full modes (D-05).
func TestDecodeWithRSFast(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	_, fullEnc := buildEncodedMiB(t, rs)
	// Partial block: 3 full chunks + a 50-byte padded trailing chunk.
	_, partialEnc := buildEncodedChunks(t, rs, 3, 50)

	tests := []struct {
		name       string
		data       []byte
		isLast     bool
		padded     bool
		fastDecode bool
	}{
		{"full-MiB fast", fullEnc, false, false, true},
		{"full-MiB full", fullEnc, false, false, false},
		{"full-MiB last padded fast", fullEnc, true, true, true},
		{"full-MiB last padded full", fullEnc, true, true, false},
		{"partial fast", partialEnc, true, true, true},
		{"partial full", partialEnc, true, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeWithRSFast(tt.data, rs, tt.isLast, tt.padded, false, tt.fastDecode)
			if err != nil {
				t.Fatalf("decodeWithRSFast: unexpected error %v", err)
			}
			want := expectedDecode(t, tt.data, rs, tt.isLast, tt.padded, tt.fastDecode)
			if !bytes.Equal(got, want) {
				t.Errorf("decodeWithRSFast output mismatch: got %d bytes, want %d bytes", len(got), len(want))
			}
		})
	}
}

// TestDecodeWithRSFastAllocs asserts the result buffer is allocated once
// (AllocsPerRun <= 1). RED before RS-02's single pre-alloc (the nil-grown
// append performs ~log2(8192) growth reallocations per 1-MiB block).
func TestDecodeWithRSFastAllocs(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	_, enc := buildEncodedMiB(t, rs)

	got := testing.AllocsPerRun(100, func() {
		_, _ = decodeWithRSFast(enc, rs, false, false, false, true)
	})
	if got > 1 {
		t.Errorf("decodeWithRSFast allocs/op = %v; want <= 1 (single pre-alloc)", got)
	}
}

// BenchmarkDecodeWithRSFast reports allocs/op for the fast-decode path over one
// full-MiB RS128 block (informational; pairs with TestDecodeWithRSFastAllocs).
func BenchmarkDecodeWithRSFast(b *testing.B) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		b.Fatalf("NewRSCodecs: %v", err)
	}
	plain := make([]byte, util.MiB)
	for i := range plain {
		plain[i] = byte(i)
	}
	var enc []byte
	for j := 0; j < util.MiB; j += encoding.RS128DataSize {
		e, encErr := encoding.Encode(rs.RS128, plain[j:j+encoding.RS128DataSize])
		if encErr != nil {
			b.Fatalf("Encode chunk at %d: %v", j, encErr)
		}
		enc = append(enc, e...)
	}

	b.ReportAllocs()
	for b.Loop() {
		_, _ = decodeWithRSFast(enc, rs, false, false, false, true)
	}
}
