//go:build openbsd

package cli

import (
	"golang.org/x/sys/unix"
)

// availableSpace returns available bytes at the given path.
// OpenBSD uses F_ prefixed field names in Statfs_t.
func availableSpace(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.F_bavail) * int64(stat.F_bsize), nil
}
