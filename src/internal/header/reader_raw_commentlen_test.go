package header

import (
	"bytes"
	"errors"
	"testing"

	"Picocrypt-NG/internal/encoding"
)

// rawHeaderWithCommentLenField builds the leading bytes of a volume header — the
// RS-encoded version field followed by an RS-encoded 5-byte comment-length field
// whose decoded value is commentLen5 verbatim. It stops after the comment-length
// field, which is all ReadHeaderRaw needs to reach the comment allocation.
func rawHeaderWithCommentLenField(t *testing.T, rs *encoding.RSCodecs, commentLen5 string) []byte {
	t.Helper()
	if len(commentLen5) != 5 {
		t.Fatalf("comment-length field must be exactly 5 bytes, got %q", commentLen5)
	}
	versionEnc, err := encoding.Encode(rs.RS5, []byte(CurrentVersion))
	if err != nil {
		t.Fatalf("encode version: %v", err)
	}
	commentLenEnc, err := encoding.Encode(rs.RS5, []byte(commentLen5))
	if err != nil {
		t.Fatalf("encode comment length: %v", err)
	}
	return append(append([]byte{}, versionEnc...), commentLenEnc...)
}

// TestReadHeaderRawRejectsNegativeCommentLength pins the SEC-01/D-02 guard on the
// guard-less raw path. A crafted comment-length field that RS-decodes to "-0001"
// makes strconv.Atoi return -1; without a bound, ReadHeaderRaw reaches
// make([]byte, 0, -1), which panics — a pre-auth crash on attacker-controlled
// input (the comment length is read and trusted before any MAC is verified).
// ReadHeader already rejects this; ReadHeaderRaw must do the same, returning a
// clean ErrInvalidCommentLength instead of panicking.
func TestReadHeaderRawRejectsNegativeCommentLength(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	input := rawHeaderWithCommentLenField(t, rs, "-0001")
	reader := NewReader(bytes.NewReader(input), rs)

	var readErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadHeaderRaw panicked on negative comment length: %v", r)
			}
		}()
		_, readErr = reader.ReadHeaderRaw()
	}()

	if readErr == nil {
		t.Fatal("ReadHeaderRaw accepted a negative comment length; want ErrInvalidCommentLength")
	}
	if !errors.Is(readErr, ErrInvalidCommentLength) {
		t.Fatalf("ReadHeaderRaw error = %v; want ErrInvalidCommentLength", readErr)
	}
}

// TestReadHeaderRawRejectsNonNumericCommentLength covers the other unvalidated
// case: a comment-length field that is not 5 digits. The old code ignored the
// strconv.Atoi error and silently treated it as length 0, parsing a header whose
// real structure it could not know. The guard now rejects it up front.
func TestReadHeaderRawRejectsNonNumericCommentLength(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}

	input := rawHeaderWithCommentLenField(t, rs, "1a2b3")
	reader := NewReader(bytes.NewReader(input), rs)

	if _, err := reader.ReadHeaderRaw(); !errors.Is(err, ErrInvalidCommentLength) {
		t.Fatalf("ReadHeaderRaw error = %v; want ErrInvalidCommentLength", err)
	}
}
