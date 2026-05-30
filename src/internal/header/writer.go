package header

import (
	"errors"
	"fmt"
	"io"

	"Picocrypt-NG/internal/encoding"
)

// Writer handles writing volume headers to an output stream
type Writer struct {
	w  io.Writer
	rs *encoding.RSCodecs
}

// NewWriter creates a header writer for the given output stream
func NewWriter(w io.Writer, rs *encoding.RSCodecs) *Writer {
	return &Writer{w: w, rs: rs}
}

// WriteHeader writes a complete volume header to the output stream.
// This writes all fields in the exact order required by the Picocrypt format.
// Returns the number of bytes written and any error.
//
// Header format (total = 789 + comments*3 bytes):
//   - Version:      15 bytes (rs5 encoded)
//   - CommentLen:   15 bytes (rs5 encoded, 5-digit decimal)
//   - Comments:     commentsLen*3 bytes (each byte rs1 encoded)
//   - Flags:        15 bytes (rs5 encoded)
//   - Salt:         48 bytes (rs16 encoded)
//   - HKDFSalt:     96 bytes (rs32 encoded)
//   - SerpentIV:    48 bytes (rs16 encoded)
//   - Nonce:        72 bytes (rs24 encoded)
//   - KeyHash:      192 bytes (rs64 encoded) - placeholder, filled later
//   - KeyfileHash:  96 bytes (rs32 encoded) - placeholder, filled later
//   - AuthTag:      192 bytes (rs64 encoded) - placeholder, filled later
func (w *Writer) WriteHeader(h *VolumeHeader) (int, error) {
	if len(h.Comments) > MaxCommentLen {
		return 0, errors.New("comments exceed maximum length")
	}

	var totalWritten int

	// Write version
	versionEnc, err := encoding.Encode(w.rs.RS5, []byte(h.Version))
	if err != nil {
		return totalWritten, fmt.Errorf("encode version: %w", err)
	}
	n, err := w.w.Write(versionEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write version: %w", err)
	}

	// Write comment length (5-digit zero-padded)
	commentsLenStr := fmt.Sprintf("%05d", len(h.Comments))
	commentLenEnc, err := encoding.Encode(w.rs.RS5, []byte(commentsLenStr))
	if err != nil {
		return totalWritten, fmt.Errorf("encode comment length: %w", err)
	}
	n, err = w.w.Write(commentLenEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write comment length: %w", err)
	}

	// Write each comment character (rs1 encoded)
	for _, c := range []byte(h.Comments) {
		commentEnc, err := encoding.Encode(w.rs.RS1, []byte{c})
		if err != nil {
			return totalWritten, fmt.Errorf("encode comment char: %w", err)
		}
		n, err = w.w.Write(commentEnc)
		totalWritten += n
		if err != nil {
			return totalWritten, fmt.Errorf("write comment char: %w", err)
		}
	}

	// Write flags
	flagsEnc, err := encoding.Encode(w.rs.RS5, h.Flags.ToBytes())
	if err != nil {
		return totalWritten, fmt.Errorf("encode flags: %w", err)
	}
	n, err = w.w.Write(flagsEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write flags: %w", err)
	}

	// Write cryptographic values
	saltEnc, err := encoding.Encode(w.rs.RS16, h.Salt)
	if err != nil {
		return totalWritten, fmt.Errorf("encode salt: %w", err)
	}
	n, err = w.w.Write(saltEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write salt: %w", err)
	}

	hkdfSaltEnc, err := encoding.Encode(w.rs.RS32, h.HKDFSalt)
	if err != nil {
		return totalWritten, fmt.Errorf("encode hkdf salt: %w", err)
	}
	n, err = w.w.Write(hkdfSaltEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write hkdf salt: %w", err)
	}

	serpentIVEnc, err := encoding.Encode(w.rs.RS16, h.SerpentIV)
	if err != nil {
		return totalWritten, fmt.Errorf("encode serpent iv: %w", err)
	}
	n, err = w.w.Write(serpentIVEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write serpent iv: %w", err)
	}

	nonceEnc, err := encoding.Encode(w.rs.RS24, h.Nonce)
	if err != nil {
		return totalWritten, fmt.Errorf("encode nonce: %w", err)
	}
	n, err = w.w.Write(nonceEnc)
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write nonce: %w", err)
	}

	// Write placeholders for authentication values (filled in after encryption)
	n, err = w.w.Write(make([]byte, KeyHashEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write key hash placeholder: %w", err)
	}

	n, err = w.w.Write(make([]byte, KeyfileHashEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write keyfile hash placeholder: %w", err)
	}

	n, err = w.w.Write(make([]byte, AuthTagEncSize))
	totalWritten += n
	if err != nil {
		return totalWritten, fmt.Errorf("write auth tag placeholder: %w", err)
	}

	return totalWritten, nil
}

// WriteAuthValues writes the authentication values to a seekable writer.
// This should be called after encryption is complete.
// offset is the position in the file where auth values begin (309 + comments*3 for v2.02)
func WriteAuthValues(w io.WriterAt, offset int64, keyHash, keyfileHash, authTag []byte, rs *encoding.RSCodecs) error {
	pos := offset

	// Write encoded key hash
	keyHashEnc, err := encoding.Encode(rs.RS64, keyHash)
	if err != nil {
		return fmt.Errorf("encode key hash: %w", err)
	}
	if _, err := w.WriteAt(keyHashEnc, pos); err != nil {
		return fmt.Errorf("write key hash: %w", err)
	}
	pos += KeyHashEncSize

	// Write encoded keyfile hash
	keyfileHashEnc, err := encoding.Encode(rs.RS32, keyfileHash)
	if err != nil {
		return fmt.Errorf("encode keyfile hash: %w", err)
	}
	if _, err := w.WriteAt(keyfileHashEnc, pos); err != nil {
		return fmt.Errorf("write keyfile hash: %w", err)
	}
	pos += KeyfileHashEncSize

	// Write encoded auth tag
	authTagEnc, err := encoding.Encode(rs.RS64, authTag)
	if err != nil {
		return fmt.Errorf("encode auth tag: %w", err)
	}
	if _, err := w.WriteAt(authTagEnc, pos); err != nil {
		return fmt.Errorf("write auth tag: %w", err)
	}

	return nil
}

// AuthValuesOffset calculates the file offset where auth values are stored
// Formula: version(15) + commentLen(15) + comments(len*3) + flags(15) +
//
//	salt(48) + hkdfSalt(96) + serpentIV(48) + nonce(72) = 309 + comments*3
func AuthValuesOffset(commentsLen int) int64 {
	return int64(VersionEncSize + CommentLenEncSize + commentsLen*3 + FlagsEncSize +
		SaltEncSize + HKDFSaltEncSize + SerpentIVEncSize + NonceEncSize)
}
