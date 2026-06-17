package volume

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	for c := range nFullChunks {
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

// Frozen decode vectors (D-05). These were computed ONCE from the real
// decodeWithRSFast over the deterministic inputs built by buildEncodedChunks /
// buildEncodedMiB, then pinned here. Pinning the OUTPUT (not re-deriving it from
// the same per-chunk loop the function uses) means a regression in the decode
// branches — chunk striding, last-chunk Unpad, full-block detection — changes the
// produced bytes and fails the test, instead of changing both sides in lockstep
// the way the previous expectedDecode reimplementation did.
//
// partialDecodeHex is the decode of buildEncodedChunks(t, rs, 2, 5): two full
// 128-byte chunks plus a 5-byte trailing chunk PKCS#7-padded to 128 before
// encoding. The trailing "a0a1a2a3a4" (5 bytes) confirms Unpad strips exactly the
// padding — a >=/> Unpad regression or a wrong last-chunk slice would change it.
const partialDecodeHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
	"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
	"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
	"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
	"0708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526" +
	"2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546" +
	"4748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263646566" +
	"6768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586" +
	"a0a1a2a3a4"

// fullDecodeSHA256 is SHA-256 of the decode of buildEncodedMiB(t, rs): one full
// 1 MiB block (8192 chunks). The decoded output is 1 MiB, so it is pinned as a
// frozen digest rather than an inline literal; any change to the full-block
// branch (the len(data)==rsEncodedBlockSize path) alters these bytes and the digest.
const fullDecodeSHA256 = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"

// TestDecodeWithRSFast asserts decodeWithRSFast output equals frozen vectors
// across the full-MiB block branch and the partial / padded-last-chunk branch, in
// both fast and full decode modes (D-05). The vectors are pinned bytes computed
// once from real code — NOT a re-implementation of the function's own branches.
func TestDecodeWithRSFast(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	wantPartial, err := hex.DecodeString(partialDecodeHex)
	if err != nil {
		t.Fatalf("decode frozen partial vector: %v", err)
	}

	// Partial block: 2 full chunks + a 5-byte padded trailing chunk.
	_, partialEnc := buildEncodedChunks(t, rs, 2, 5)
	for _, fastDecode := range []bool{true, false} {
		name := "partial full"
		if fastDecode {
			name = "partial fast"
		}
		t.Run(name, func(t *testing.T) {
			got, err := decodeWithRSFast(partialEnc, rs, true, true, false, fastDecode)
			if err != nil {
				t.Fatalf("decodeWithRSFast: unexpected error %v", err)
			}
			if !bytes.Equal(got, wantPartial) {
				t.Errorf("partial decode mismatch:\n got %s\nwant %s", hex.EncodeToString(got), partialDecodeHex)
			}
		})
	}

	// Full 1 MiB block branch, both decode modes; the output is pinned by digest.
	_, fullEnc := buildEncodedMiB(t, rs)
	for _, fastDecode := range []bool{true, false} {
		name := "full-MiB full"
		if fastDecode {
			name = "full-MiB fast"
		}
		t.Run(name, func(t *testing.T) {
			got, err := decodeWithRSFast(fullEnc, rs, false, false, false, fastDecode)
			if err != nil {
				t.Fatalf("decodeWithRSFast: unexpected error %v", err)
			}
			sum := sha256.Sum256(got)
			if gotHex := hex.EncodeToString(sum[:]); gotHex != fullDecodeSHA256 {
				t.Errorf("full-MiB decode digest mismatch: got %s, want %s (len=%d)", gotHex, fullDecodeSHA256, len(got))
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
