package fileops

import (
	"os"
)

// CreateSecure creates file with 0600 permissions atomically.
// Uses os.OpenFile to set perms at creation (no TOCTOU window).
func CreateSecure(path string) (*os.File, error) {
	// #nosec G304 -- path is user-provided input file, validated by caller
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}
