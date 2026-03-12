package fileops

import (
	"fmt"
	"os"
)

// CreateSecure creates file with 0600 permissions atomically.
// Uses os.OpenFile to set perms at creation (no TOCTOU window).
func CreateSecure(path string) (*os.File, error) {
	// #nosec G304 -- path is user-provided input file, validated by caller
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// CreateSecureNoSymlink creates or truncates a file unless the leaf already exists as a symlink.
func CreateSecureNoSymlink(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to open symlink: %s", path)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("path exists as directory: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	// #nosec G304 -- path is user-provided input file, validated by caller
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}
