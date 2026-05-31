package ui

import (
	"io"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

// previewHeader parses a volume header for the GUI decrypt preview using the
// single validated parser (*header.Reader).ReadHeader(). It is pure and
// UI-free (no *App, no Fyne, no widget side effects) so it is unit-testable and
// shares the exact comment-length (^\d{5}$ + D-02 bound) and version (anchored
// header.MatchVersion) guards used at decrypt time (SEC-01, UI-01, D-01).
//
// It returns the full *header.ReadResult so the caller can distinguish a hard
// parse error (err != nil) from a soft "comments corrupted" condition
// (res.DecodeError != nil with a usable header) and reproduce the existing UX
// strings. Routing through ReadHeader (not ReadHeaderRaw) is deliberate:
// ReadHeader has the ^\d{5}$ comment-length guard before allocating.
func previewHeader(r io.Reader, rs *encoding.RSCodecs) (*header.ReadResult, error) {
	return header.NewReader(r, rs).ReadHeader()
}
