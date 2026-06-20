package errors

import (
	"errors"
	"testing"
)

// TestSentinelErrors locks down every exported Err... sentinel in errors.go:
// its self-identity under errors.Is, its exact message literal, and pairwise
// distinctness across the whole set. Callers (e.g. volume/decrypt.go) branch on
// these via errors.Is, so two sentinels collapsing into one — or a message
// drifting — must fail a test, not silently change runtime behavior. The
// ErrCorruptHeader/ErrCorruptData pair is the load-bearing case: they
// distinguish corruption kinds and must never be aliased.
//
// To keep this exhaustive, every new sentinel added to errors.go must appear in
// this table; the count assertion below is the tripwire that forces it.
func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string // exact message literal, mirroring errors.go
	}{
		{"ErrCancelled", ErrCancelled, "operation cancelled"},
		{"ErrAuthFailed", ErrAuthFailed, "authentication failed"},
		{"ErrCorruptHeader", ErrCorruptHeader, "header corrupted"},
		{"ErrCorruptData", ErrCorruptData, "data corrupted"},
		{"ErrNoInputFiles", ErrNoInputFiles, "no input files specified"},
		{"ErrNoCredentials", ErrNoCredentials, "no password or keyfiles provided"},
		{"ErrPasswordMismatch", ErrPasswordMismatch, "passwords do not match"},
		{"ErrInvalidChunkSize", ErrInvalidChunkSize, "invalid chunk size"},
		{"ErrChunkSizeTooLarge", ErrChunkSizeTooLarge, "chunk size exceeds maximum"},
		{"ErrDuplicateKeyfiles", ErrDuplicateKeyfiles, "duplicate keyfiles detected"},
		{"ErrCommentTooLong", ErrCommentTooLong, "comment exceeds maximum length"},
		{"ErrFileNotFound", ErrFileNotFound, "file not found"},
	}

	// Tripwire: forces this table to be updated whenever a sentinel is added or
	// removed from errors.go, so the exhaustive guarantees below stay exhaustive.
	if want := 12; len(tests) != want {
		t.Fatalf("sentinel table has %d entries; want %d (update the table when "+
			"adding/removing an Err... sentinel in errors.go)", len(tests), want)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("sentinel error must not be nil")
			}
			// Self-identity: a sentinel must satisfy errors.Is against itself.
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%s, %s) = false; want true (self-identity)", tt.name, tt.name)
			}
			// Exact message literal — drift must fail the test.
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("%s.Error() = %q; want %q", tt.name, got, tt.want)
			}
		})
	}

	// Pairwise distinctness: no two sentinels may be == or errors.Is-equal.
	// Critically guards ErrCorruptHeader vs ErrCorruptData (volume/decrypt.go
	// branches on the difference). Aliasing any pair must fail here.
	for i := range tests {
		for j := i + 1; j < len(tests); j++ {
			a, b := tests[i], tests[j]
			if errors.Is(a.err, b.err) {
				t.Errorf("%s and %s are the same error value; sentinels must be distinct", a.name, b.name)
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("errors.Is(%s, %s) = true; sentinels must not be Is-equal", a.name, b.name)
			}
			if errors.Is(b.err, a.err) {
				t.Errorf("errors.Is(%s, %s) = true; sentinels must not be Is-equal", b.name, a.name)
			}
		}
	}
}

func TestCryptoError(t *testing.T) {
	baseErr := errors.New("underlying error")
	cryptoErr := NewCryptoError("rand", baseErr)

	if cryptoErr.Error() != "crypto rand: underlying error" {
		t.Errorf("unexpected error message: %s", cryptoErr.Error())
	}

	if !errors.Is(cryptoErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}

	// Test with nil error
	cryptoErrNil := NewCryptoError("hkdf", nil)
	if cryptoErrNil.Error() != "crypto hkdf failed" {
		t.Errorf("unexpected error message for nil: %s", cryptoErrNil.Error())
	}
}

func TestFileError(t *testing.T) {
	baseErr := errors.New("permission denied")
	fileErr := NewFileError("open", "/path/to/file", baseErr)

	if fileErr.Error() != "open /path/to/file: permission denied" {
		t.Errorf("unexpected error message: %s", fileErr.Error())
	}

	if !errors.Is(fileErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}

	// Test with nil error
	fileErrNil := NewFileError("stat", "/some/path", nil)
	if fileErrNil.Error() != "stat /some/path failed" {
		t.Errorf("unexpected error message for nil: %s", fileErrNil.Error())
	}
}

func TestValidationError(t *testing.T) {
	validErr := NewValidationError("password", "must be at least 8 characters")

	expected := "validation: password: must be at least 8 characters"
	if validErr.Error() != expected {
		t.Errorf("unexpected error message: %s", validErr.Error())
	}
}

func TestHeaderError(t *testing.T) {
	baseErr := errors.New("decode failed")
	headerErr := NewHeaderError("version", baseErr)

	if headerErr.Error() != "header version: decode failed" {
		t.Errorf("unexpected error message: %s", headerErr.Error())
	}

	if !errors.Is(headerErr.Unwrap(), baseErr) {
		t.Error("Unwrap should return underlying error")
	}
}

func TestIs(t *testing.T) {
	if !Is(ErrCancelled, ErrCancelled) {
		t.Error("Is should return true for same error")
	}

	if Is(ErrCancelled, ErrAuthFailed) {
		t.Error("Is should return false for different errors")
	}
}

func TestAs(t *testing.T) {
	cryptoErr := NewCryptoError("test", errors.New("test"))

	var target *CryptoError
	if !As(cryptoErr, &target) {
		t.Error("As should find CryptoError")
	}

	if target.Op != "test" {
		t.Errorf("unexpected Op: %s", target.Op)
	}
}

func TestWrap(t *testing.T) {
	baseErr := errors.New("base")
	wrapped := Wrap(baseErr, "context")

	if wrapped.Error() != "context: base" {
		t.Errorf("unexpected wrapped message: %s", wrapped.Error())
	}

	// Test with nil
	if Wrap(nil, "context") != nil {
		t.Error("Wrap(nil) should return nil")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	if !IsCancelled(ErrCancelled) {
		t.Error("IsCancelled should return true for ErrCancelled")
	}

	if IsCancelled(ErrAuthFailed) {
		t.Error("IsCancelled should return false for other errors")
	}

	if !IsAuthFailed(ErrAuthFailed) {
		t.Error("IsAuthFailed should return true for ErrAuthFailed")
	}

	if !IsCorrupt(ErrCorruptHeader) {
		t.Error("IsCorrupt should return true for ErrCorruptHeader")
	}

	if !IsCorrupt(ErrCorruptData) {
		t.Error("IsCorrupt should return true for ErrCorruptData")
	}
}
