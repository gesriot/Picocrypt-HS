package ui

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"errors"
	"testing"
)

// rs5Encode RS5-encodes a 5-byte field for crafting header bytes inline.
func rs5Encode(t *testing.T, rs *encoding.RSCodecs, field []byte) []byte {
	t.Helper()
	if len(field) != 5 {
		t.Fatalf("rs5Encode: want 5 bytes, got %d", len(field))
	}
	enc, err := encoding.Encode(rs.RS5, field)
	if err != nil {
		t.Fatalf("rs5Encode: %v", err)
	}
	return enc
}

// rs1Encode RS1-encodes a single comment byte (1 -> 3 bytes).
func rs1Encode(t *testing.T, rs *encoding.RSCodecs, b byte) []byte {
	t.Helper()
	enc, err := encoding.Encode(rs.RS1, []byte{b})
	if err != nil {
		t.Fatalf("rs1Encode: %v", err)
	}
	return enc
}

// craftHeaderPrefix builds the version + comment-length + comments + flags
// prefix of a .pcv header (the portion the GUI preview reads). The remaining
// crypto fields are filled with RS5/zero padding so a full ReadHeader can run
// past the comments without an early EOF when needed.
func craftPreviewBytes(t *testing.T, rs *encoding.RSCodecs, version, commentLen string, comment string, flags []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(rs5Encode(t, rs, []byte(version)))
	buf.Write(rs5Encode(t, rs, []byte(commentLen)))
	for i := range len(comment) {
		buf.Write(rs1Encode(t, rs, comment[i]))
	}
	buf.Write(rs5Encode(t, rs, flags))
	return buf.Bytes()
}

// TestPreviewVersionRegexAndNonBlocking exercises the pure previewHeader wrapper
// and the shared header.MatchVersion helper (UI-01/QUAL-01). previewHeader must
// be UI-free (takes an io.Reader + codecs, no *App) so it is unit-testable and
// shares the validated parser's comment-length guard. A malformed comment-length
// field must surface a header error instead of over-allocating (SEC-01).
func TestPreviewVersionRegexAndNonBlocking(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	// Shared anchored regex behaviour, via the header helper.
	if !header.MatchVersion([]byte("v2.09")) {
		t.Error("MatchVersion should accept v2.09")
	}
	if header.MatchVersion([]byte("v2.0X")) {
		t.Error("MatchVersion should reject anchored-mismatch v2.0X")
	}

	t.Run("valid header parses comments", func(t *testing.T) {
		raw := craftPreviewBytes(t, rs, "v2.09", "00002", "hi", []byte{0, 0, 0, 0, 0})
		// Pad the rest of the base header so ReadHeader reaches the end cleanly.
		raw = append(raw, make([]byte, header.BaseHeaderSize)...)
		res, err := previewHeader(bytes.NewReader(raw), rs)
		if err != nil {
			t.Fatalf("previewHeader returned error on valid header: %v", err)
		}
		if res == nil || res.Header == nil {
			t.Fatal("previewHeader returned nil result/header on valid input")
		}
		if res.Header.Comments != "hi" {
			t.Errorf("Comments = %q; want %q", res.Header.Comments, "hi")
		}
	})

	t.Run("malformed comment length is rejected without over-alloc", func(t *testing.T) {
		// "-0001" is not five ASCII digits; the validated parser rejects it via
		// the ^\d{5}$ guard before any comment allocation.
		raw := craftPreviewBytes(t, rs, "v2.09", "-0001", "", []byte{0, 0, 0, 0, 0})
		_, err := previewHeader(bytes.NewReader(raw), rs)
		if !errors.Is(err, header.ErrInvalidCommentLength) {
			t.Fatalf("previewHeader err = %v; want ErrInvalidCommentLength", err)
		}
	})
}
