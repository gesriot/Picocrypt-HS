package header

import (
	"bytes"
	"errors"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// TestMatchVersionAnchored verifies the shared version helper uses the single
// anchored pattern ^v\d\.\d{2}$ (QUAL-01/D-03). The anchoring matters: a
// trailing-garbage 5-byte value such as "v2.0X" must be rejected, unlike the
// historically-unanchored UI copy (Pitfall 5).
func TestMatchVersionAnchored(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid v2.09", "v2.09", true},
		{"valid v2.10", "v2.10", true},
		{"valid non-current v3.11", "v3.11", true},
		{"valid v1.49", "v1.49", true},
		{"trailing garbage", "v2.0X", false},
		{"too long", "v2.099", false},
		{"missing v", "2.09", false},
		{"leading space", " v2.0", false},
		{"empty", "", false},
		{"two digit major", "v22.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchVersion([]byte(tc.in)); got != tc.want {
				t.Errorf("MatchVersion(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

// encodeField RS5-encodes a 5-byte field for crafting header bytes inline.
func encodeField(t *testing.T, rs *encoding.RSCodecs, field []byte) []byte {
	t.Helper()
	if len(field) != 5 {
		t.Fatalf("encodeField: want 5 bytes, got %d", len(field))
	}
	enc, err := encoding.Encode(rs.RS5, field)
	if err != nil {
		t.Fatalf("encodeField: %v", err)
	}
	return enc
}

// TestReadHeaderRejectsBadCommentLen verifies the comment-length guard rejects
// a non-5-digit field and, per D-02, never over-allocates. A version field
// followed by a comment-length field that is not exactly 5 digits must return
// ErrInvalidCommentLength before any comment allocation occurs.
func TestReadHeaderRejectsBadCommentLen(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	version := encodeField(t, rs, []byte("v2.09"))

	// Comment-length field that decodes to something that is NOT five ASCII
	// digits (a leading '-' simulating a "negative"-looking field). The guard
	// must reject this and return ErrInvalidCommentLength.
	badLen := encodeField(t, rs, []byte("-0001"))

	var buf bytes.Buffer
	buf.Write(version)
	buf.Write(badLen)

	reader := NewReader(bytes.NewReader(buf.Bytes()), rs)
	_, err = reader.ReadHeader()
	if !errors.Is(err, ErrInvalidCommentLength) {
		t.Fatalf("ReadHeader() err = %v; want ErrInvalidCommentLength", err)
	}
}

// TestReadHeaderCommentLenBoundConstant ensures the D-02 bound references the
// MaxCommentLen constant (defense-in-depth, not a literal). A well-formed
// 5-digit field at the constant's max (99999) is permitted by the digit guard;
// the bound only adds rejection for out-of-range values that the digit guard
// could miss on guard-less paths. Here we assert MaxCommentLen is the canonical
// cap so the bound and the guard agree.
func TestReadHeaderCommentLenBoundConstant(t *testing.T) {
	if MaxCommentLen != 99999 {
		t.Fatalf("MaxCommentLen = %d; want 99999 (D-02 bound source of truth)", MaxCommentLen)
	}
}
