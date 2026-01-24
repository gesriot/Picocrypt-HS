//go:build darwin || dragonfly || freebsd || linux || netbsd || solaris

package cli

import (
	"golang.org/x/sys/unix"
)

// availableSpace returns available bytes at the given path.
func availableSpace(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	// Bavail = blocks available to unprivileged users
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
