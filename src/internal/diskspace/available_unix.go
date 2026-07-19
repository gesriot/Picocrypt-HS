//go:build darwin || linux

package diskspace

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

// Available returns available bytes at the given path.
// darwin and linux expose an unsigned Bavail in Statfs_t.
func Available(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	// Bavail = blocks available to unprivileged users
	// Safe conversion: check for overflow before multiplication
	if stat.Bavail > uint64(math.MaxInt64) {
		return 0, errors.New("available blocks exceeds int64 max")
	}
	blocks := int64(stat.Bavail)
	bsize := int64(stat.Bsize) //nolint:unconvert // Bsize type varies across unix (already int64 on linux); kept for portability
	// Check multiplication overflow
	if bsize > 0 && blocks > math.MaxInt64/bsize {
		return 0, errors.New("available space exceeds int64 max")
	}
	return blocks * bsize, nil
}
