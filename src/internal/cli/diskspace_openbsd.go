//go:build openbsd

package cli

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

// availableSpace returns available bytes at the given path.
// OpenBSD uses F_ prefixed field names in Statfs_t.
func availableSpace(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	// Convert to int64 (OpenBSD types vary by arch: int64 on amd64, uint32/int64 on 386)
	blocks := int64(stat.F_bavail)
	bsize := int64(stat.F_bsize)
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
