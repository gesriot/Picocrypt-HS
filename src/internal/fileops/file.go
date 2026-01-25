package fileops

import (
	"os"
)

// CreateSecure creates file with 0600 permissions atomically.
// Uses os.OpenFile to set perms at creation (no TOCTOU window).
func CreateSecure(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}
