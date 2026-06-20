package encoding

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Picocrypt/infectious"
)

func TestNewRSCodecs(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Verify all codecs were initialized
	if codecs.RS1 == nil || codecs.RS5 == nil || codecs.RS16 == nil ||
		codecs.RS24 == nil || codecs.RS32 == nil || codecs.RS64 == nil ||
		codecs.RS128 == nil {
		t.Fatal("NewRSCodecs() returned nil codec(s)")
	}

	// Verify codec parameters
	if codecs.RS1.Required() != 1 || codecs.RS1.Total() != 3 {
		t.Errorf("RS1: got Required=%d, Total=%d; want 1, 3", codecs.RS1.Required(), codecs.RS1.Total())
	}
	if codecs.RS5.Required() != 5 || codecs.RS5.Total() != 15 {
		t.Errorf("RS5: got Required=%d, Total=%d; want 5, 15", codecs.RS5.Required(), codecs.RS5.Total())
	}
	if codecs.RS16.Required() != 16 || codecs.RS16.Total() != 48 {
		t.Errorf("RS16: got Required=%d, Total=%d; want 16, 48", codecs.RS16.Required(), codecs.RS16.Total())
	}
	if codecs.RS24.Required() != 24 || codecs.RS24.Total() != 72 {
		t.Errorf("RS24: got Required=%d, Total=%d; want 24, 72", codecs.RS24.Required(), codecs.RS24.Total())
	}
	if codecs.RS32.Required() != 32 || codecs.RS32.Total() != 96 {
		t.Errorf("RS32: got Required=%d, Total=%d; want 32, 96", codecs.RS32.Required(), codecs.RS32.Total())
	}
	if codecs.RS64.Required() != 64 || codecs.RS64.Total() != 192 {
		t.Errorf("RS64: got Required=%d, Total=%d; want 64, 192", codecs.RS64.Required(), codecs.RS64.Total())
	}
	if codecs.RS128.Required() != 128 || codecs.RS128.Total() != 136 {
		t.Errorf("RS128: got Required=%d, Total=%d; want 128, 136", codecs.RS128.Required(), codecs.RS128.Total())
	}
}

func TestEncodeWrongSizeReturnsError(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	tests := []struct {
		name string
		rs   *infectious.FEC
		size int // != rs.Required()
	}{
		{"RS128 too small", codecs.RS128, 127},
		{"RS128 too large", codecs.RS128, 129},
		{"RS128 multiple-of-k", codecs.RS128, 256}, // multiple of k=128: passes infectious but panics in callback (index case)
		{"RS5 wrong", codecs.RS5, 4},
		{"RS1 wrong", codecs.RS1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encode(tt.rs, make([]byte, tt.size))
			if err == nil {
				t.Errorf("Encode(size=%d) = nil error; want non-nil", tt.size)
			}
		})
	}

	// Correct size still succeeds, byte-identical length to pre-change.
	enc, err := Encode(codecs.RS128, make([]byte, 128))
	if err != nil {
		t.Fatalf("correct-size Encode: unexpected err=%v", err)
	}
	if len(enc) != 136 {
		t.Errorf("correct-size Encode: len=%d; want 136", len(enc))
	}
}

// goldenRS128Input is a fixed 128-byte input (byte i = i*7+1 mod 256) whose
// RS128 encoding is frozen below. Shared by the golden-vector test.
func goldenRS128Input() []byte {
	in := make([]byte, RS128DataSize)
	for i := range in {
		in[i] = byte(i*7 + 1)
	}
	return in
}

// TestRS128EncodeGoldenVector pins the RS128 payload encoder's output to a
// frozen byte vector. The RS128 codec (infectious FEC(128,136)) is the exact
// one the legacy Picocrypt .pcv format uses, so this freezes the on-disk
// payload encode format: any drift in parity or layout is caught here directly,
// not only transitively via roundtrip self-consistency.
//
// RS128 is a *systematic* code: output bytes 0..127 are the input verbatim
// (this is why Decode's fast path returns data[:128]); bytes 128..135 are the
// 8 parity bytes. Both properties are asserted.
func TestRS128EncodeGoldenVector(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	input := goldenRS128Input()
	got, err := Encode(codecs.RS128, input)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(got) != RS128EncodedSize {
		t.Fatalf("Encode len = %d; want %d", len(got), RS128EncodedSize)
	}

	// Systematic property: first 128 output bytes equal the input verbatim.
	if !bytes.Equal(got[:RS128DataSize], input) {
		t.Errorf("RS128 not systematic:\n got[:128]=%x\nwant       %x", got[:RS128DataSize], input)
	}

	// Frozen full 136-byte block (128 systematic + 8 parity).
	wantFull, err := hex.DecodeString(
		"01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da" +
			"e1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3ba" +
			"c1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939a" +
			"a1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a" +
			"a5d74e94add3b8cd")
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if !bytes.Equal(got, wantFull) {
		t.Errorf("RS128 golden mismatch (encode format drift):\n got  %x\nwant %x", got, wantFull)
	}
}

func TestEncodeIntoGoldenVectors(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// EncodeInto output is pinned to independent golden vectors rather than
	// compared against Encode (which merely wraps EncodeInto, making that a
	// self-comparison that survives any corruption of the shared rs.Encode
	// callback). Inputs are data[i]=byte(i*7+1); the vectors below are frozen
	// hex pinned from the real encoder. The RS128 vector equals
	// TestRS128EncodeGoldenVector's wantFull, so EncodeInto and Encode are
	// cross-checked against the same frozen on-disk format without a tautology,
	// and any drift in parity/layout for ANY codec is caught here directly.
	cases := []struct {
		name   string
		rs     *infectious.FEC
		golden string // frozen EncodeInto output, hex
	}{
		{"RS1", codecs.RS1, "010101"},
		{"RS5", codecs.RS5, "01080f161db7d775ff302fd8df8862"},
		{"RS16", codecs.RS16, "01080f161d242b323940474e555c636a" +
			"ae9b1a3e844e245e00fc53e8555bec9bc60161db82e09195a2bfd287c652afca"},
		{"RS24", codecs.RS24, "01080f161d242b323940474e555c636a71787f868d949ba2" +
			"bfdb84891f55112e47f06919e11593e87b2ec210d70198e2" +
			"ce796547f5bc60d922c1c0a17444484160eac65ffe76e029"},
		{"RS32", codecs.RS32, "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da" +
			"7596357a44436d24e306dd71aab840a7a3ddfe5ab0505017" +
			"648982124bfc79e6810f673629d66c48ea85637d127513f0430c73eff09a174f9fd25d2687bbd603"},
		{"RS64", codecs.RS64, "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da" +
			"e1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3ba" +
			"a7b7ba564e1eb102a42e96d4d5e235b57e7ef7ec82e16e1de253da8fd6aaf8cb" +
			"7409d291018dc607a4b2e8c812d2f4cf7e657f0108f7ac1e9461e4fc933096918fc20ddd1ecdfeb1" +
			"a84cefa772b43e35990caedcf7fdbe2ba15c17020ab3ed42ecd9ff9180f76bd5d2a15bfab2e857345" +
			"7218bbaa72de809d604ee943825fc34"},
		{"RS128", codecs.RS128, "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da" +
			"e1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3ba" +
			"c1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939a" +
			"a1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a" +
			"a5d74e94add3b8cd"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := make([]byte, c.rs.Required())
			for i := range data {
				data[i] = byte(i*7 + 1) // non-trivial, deterministic content
			}

			want, err := hex.DecodeString(c.golden)
			if err != nil {
				t.Fatalf("decode golden: %v", err)
			}

			dst := make([]byte, c.rs.Total())
			if err := EncodeInto(dst, c.rs, data); err != nil {
				t.Fatalf("EncodeInto: %v", err)
			}
			if len(dst) != c.rs.Total() {
				t.Errorf("EncodeInto len = %d; want %d", len(dst), c.rs.Total())
			}
			if !bytes.Equal(dst, want) {
				t.Errorf("EncodeInto golden mismatch (encode format drift):\n got  %x\nwant %x", dst, want)
			}
		})
	}

	// Precondition errors, never panic.
	if err := EncodeInto(make([]byte, 136), codecs.RS128, make([]byte, 127)); err == nil {
		t.Error("EncodeInto(wrong data size): expected error, got nil")
	}
	if err := EncodeInto(make([]byte, 135), codecs.RS128, make([]byte, 128)); err == nil {
		t.Error("EncodeInto(wrong dst size): expected error, got nil")
	}
}

func TestDecodeWrongSizeReturnsError(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Decode operates on attacker-controlled .pcv bytes; a slice whose length
	// does not match the codec's Total() must return an error, never panic.
	// Mirrors the Encode precondition (TestEncodeWrongSizeReturnsError).
	tests := []struct {
		name       string
		rs         *infectious.FEC
		size       int // != rs.Total()
		fastDecode bool
	}{
		{"RS128 short correct-path", codecs.RS128, 100, false},
		{"RS128 short fast-path", codecs.RS128, 100, true},
		{"RS128 too large", codecs.RS128, 200, false},
		{"RS5 short", codecs.RS5, 4, false},
		{"RS1 short", codecs.RS1, 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.rs, make([]byte, tt.size), tt.fastDecode)
			if err == nil {
				t.Errorf("Decode(size=%d, fast=%v) = nil error; want non-nil", tt.size, tt.fastDecode)
			}
		})
	}

	// Correct size still round-trips (no regression on the valid path).
	enc, err := Encode(codecs.RS128, make([]byte, 128))
	if err != nil {
		t.Fatalf("setup Encode: %v", err)
	}
	if _, err := Decode(codecs.RS128, enc, false); err != nil {
		t.Errorf("correct-size Decode: unexpected err=%v", err)
	}
}

func TestRSEncodeDecodeRS128(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test RS128 specifically (most commonly used for payload)
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}

	// Encode
	encoded, err := Encode(codecs.RS128, data)
	if err != nil {
		t.Fatalf("Encode(RS128) failed: %v", err)
	}
	if len(encoded) != 136 {
		t.Errorf("Encode(RS128) length = %d; want 136", len(encoded))
	}

	// Decode with fastDecode=false (full decode)
	decoded, err := Decode(codecs.RS128, encoded, false)
	if err != nil {
		t.Fatalf("Decode(RS128) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("Decode(RS128) did not recover original data")
	}

	// Decode with fastDecode=true (skip RS, just return first 128 bytes)
	decoded, err = Decode(codecs.RS128, encoded, true)
	if err != nil {
		t.Fatalf("Decode(RS128, fastDecode=true) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("Decode(RS128, fastDecode=true) did not recover original data")
	}

	// Recovery: RS128 = FEC(128,136) corrects up to 4 corrupted bytes. The
	// correct path (fastDecode=false) must repair exactly-4 corruption silently.
	// Mutation caught: dropping payload error-correction (e.g. always taking the
	// fast slice) leaves the 4 flipped bytes in place and this fails.
	recover4 := make([]byte, len(encoded))
	copy(recover4, encoded)
	for i := range 4 {
		recover4[i*30] ^= 0xFF
	}
	decoded, err = Decode(codecs.RS128, recover4, false)
	if err != nil {
		t.Fatalf("Decode(RS128, 4-byte corruption) returned err=%v; want nil (recoverable)", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Error("Decode(RS128, 4-byte corruption) did not recover original data")
	}

	// Detection: 5 corrupted bytes exceed RS128's budget. The correct path must
	// surface a non-nil error (the format-integrity signal the decrypt pipeline
	// relies on to trigger force-decode / report tampering).
	// Mutation caught: Decode swallowing rs.Decode's error on the payload codec.
	corrupt5 := make([]byte, len(encoded))
	copy(corrupt5, encoded)
	for i := range 5 {
		corrupt5[i*20] ^= 0xFF
	}
	if _, err := Decode(codecs.RS128, corrupt5, false); err == nil {
		t.Error("Decode(RS128, 5-byte corruption) = nil error; want non-nil (beyond correction budget)")
	}

	// Fast-path contrast: on the SAME 5-byte-corrupted block, fastDecode=true
	// skips correction entirely and hands back the raw first 128 bytes with nil
	// error. This pins the performance shortcut: it neither corrects nor detects.
	// Mutation caught: the fast path silently running error correction (it would
	// then differ from the raw corrupted prefix).
	fast, err := Decode(codecs.RS128, corrupt5, true)
	if err != nil {
		t.Fatalf("Decode(RS128, 5-byte corruption, fastDecode=true) returned err=%v; want nil", err)
	}
	if !bytes.Equal(fast, corrupt5[:128]) {
		t.Error("Decode(RS128, fastDecode=true) ran correction; want raw corrupted data[:128]")
	}
}

// TestRSEncodeDecodeRS1 pins the failure mode of the comment-symbol codec
// RS1 = FEC(1,3). It corrects 1 corrupted byte but CANNOT detect 2: with k=1,
// a single surviving share already equals Required, so Berlekamp-Welch
// reconstructs a self-consistent (but WRONG) degree-0 polynomial and reports
// success. RS1's detection ceiling is therefore intentionally excluded from the
// table-driven TestRSErrorCorrection and asserted here instead.
func TestRSEncodeDecodeRS1(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	// Test RS1 (used for comment symbols)
	data := []byte("A")

	encoded, err := Encode(codecs.RS1, data)
	if err != nil {
		t.Fatalf("Encode(RS1) failed: %v", err)
	}
	if len(encoded) != 3 {
		t.Errorf("Encode(RS1) length = %d; want 3", len(encoded))
	}

	// Clean round-trip still works.
	decoded, err := Decode(codecs.RS1, encoded, false)
	if err != nil {
		t.Fatalf("Decode(RS1) failed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Decode(RS1) = %q; want %q", decoded, data)
	}

	// 1-byte corruption is within budget: recovered exactly, nil error.
	// Mutation caught: a regression that drops RS1's single-error correction.
	corrupt1 := []byte{encoded[0] ^ 0xFF, encoded[1], encoded[2]}
	decoded, err = Decode(codecs.RS1, corrupt1, false)
	if err != nil {
		t.Fatalf("Decode(RS1, 1-byte corruption) returned err=%v; want nil (recoverable)", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("Decode(RS1, 1-byte corruption) = %q; want %q", decoded, data)
	}

	// 2-byte corruption: k=1 -> the 1 surviving share == Required, so BW
	// reconstructs a CONSISTENT but WRONG polynomial. Decode returns nil error
	// AND wrong data — RS1 cannot DETECT 2-byte corruption. This documents a
	// real limit of the comment-symbol codec.
	// Mutation caught: any future change to RS1's behavior (e.g. widening it so
	// it could detect this) flips one of these assertions and forces review.
	corrupt2 := []byte{encoded[0] ^ 0xFF, encoded[1] ^ 0xFF, encoded[2]}
	decoded, err = Decode(codecs.RS1, corrupt2, false)
	if err != nil {
		t.Fatalf("Decode(RS1, 2-byte corruption) returned err=%v; want nil (cannot detect)", err)
	}
	if bytes.Equal(decoded, data) {
		t.Error("Decode(RS1, 2-byte corruption) recovered original; want WRONG data (RS1 has no 2-error detection)")
	}
}

// TestRSErrorCorrection pins the exact error-correction budget of every codec
// that has a meaningful detection threshold: corrupting `budget` bytes must
// recover the original silently, and corrupting `budget+1` must surface a
// non-nil error. RS1 is excluded — it cannot detect its over-budget case at all
// (see TestRSEncodeDecodeRS1).
//
// Budgets are NOT total/3: RS128 = FEC(128,136) carries only 8 parity bytes and
// corrects 4 (8/2), whereas the 1:3 codecs correct k. Pinning the literal budget
// per codec catches an off-by-one in any codec's correction strength and catches
// Decode dropping its error report at the threshold.
func TestRSErrorCorrection(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	cases := []struct {
		name   string
		codec  *infectious.FEC
		k      int // data size
		budget int // max correctable byte errors
	}{
		{"RS5", codecs.RS5, 5, 5},
		{"RS16", codecs.RS16, 16, 16},
		{"RS24", codecs.RS24, 24, 24},
		{"RS32", codecs.RS32, 32, 32},
		{"RS64", codecs.RS64, 64, 64},
		{"RS128", codecs.RS128, 128, 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.k)
			for i := range data {
				data[i] = byte(i*37 + 11) // deterministic, non-trivial
			}
			encoded, err := Encode(tc.codec, data)
			if err != nil {
				t.Fatalf("Encode(%s) failed: %v", tc.name, err)
			}

			// Corrupt exactly `budget` distinct bytes -> must recover silently.
			atBudget := make([]byte, len(encoded))
			copy(atBudget, encoded)
			for i := range tc.budget {
				atBudget[i] ^= 0xFF
			}
			decoded, err := Decode(tc.codec, atBudget, false)
			if err != nil {
				t.Fatalf("Decode(%s, %d-byte corruption) err=%v; want nil (within budget)", tc.name, tc.budget, err)
			}
			if !bytes.Equal(decoded, data) {
				t.Errorf("Decode(%s, %d-byte corruption) did not recover original data", tc.name, tc.budget)
			}

			// Corrupt budget+1 distinct bytes -> must report a non-nil error.
			overBudget := make([]byte, len(encoded))
			copy(overBudget, encoded)
			for i := range tc.budget + 1 {
				overBudget[i] ^= 0xFF
			}
			if _, err := Decode(tc.codec, overBudget, false); err == nil {
				t.Errorf("Decode(%s, %d-byte corruption) = nil error; want non-nil (beyond budget)", tc.name, tc.budget+1)
			}
		})
	}
}

func TestRSAllCodecsRoundtrip(t *testing.T) {
	codecs, err := NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs() failed: %v", err)
	}

	testCases := []struct {
		name     string
		codec    *infectious.FEC
		dataSize int
	}{
		{"RS1", codecs.RS1, 1},
		{"RS5", codecs.RS5, 5},
		{"RS16", codecs.RS16, 16},
		{"RS24", codecs.RS24, 24},
		{"RS32", codecs.RS32, 32},
		{"RS64", codecs.RS64, 64},
		{"RS128", codecs.RS128, 128},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test data
			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = byte((i * 37) % 256) // Use a pattern
			}

			// Dispatch through the stored codec — the table drives the full
			// execution path (no switch-by-name; a typo'd case can't silently
			// exercise the zero-value path).
			encoded, encErr := Encode(tc.codec, data)
			decoded, decErr := Decode(tc.codec, encoded, false)

			if encErr != nil {
				t.Fatalf("Encode failed: %v", encErr)
			}
			if decErr != nil {
				t.Fatalf("Decode failed: %v", decErr)
			}

			// Check encoded length
			if len(encoded) != tc.codec.Total() {
				t.Errorf("Encoded length = %d; want %d", len(encoded), tc.codec.Total())
			}

			// Check decoded data matches original
			if !bytes.Equal(decoded, data) {
				t.Error("Decoded data does not match original")
			}
		})
	}
}
