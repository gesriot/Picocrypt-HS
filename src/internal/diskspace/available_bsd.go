//go:build freebsd || dragonfly

package diskspace

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

// Available returns available bytes at the given path.
// FreeBSD and DragonFly expose a signed Bavail in Statfs_t (unlike
// darwin/linux), so the overflow guard mirrors the OpenBSD variant.
func Available(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	blocks := int64(stat.Bavail)
	bsize := int64(stat.Bsize)
	// Check for negative values (invalid stats)
	if blocks < 0 || bsize <= 0 {
		return 0, errors.New("invalid filesystem stats")
	}
	// Check multiplication overflow
	if blocks > math.MaxInt64/bsize {
		return 0, errors.New("available space exceeds int64 max")
	}
	return blocks * bsize, nil
}
