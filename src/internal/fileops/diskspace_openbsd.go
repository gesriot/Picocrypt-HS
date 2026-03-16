//go:build openbsd

package fileops

import (
	"errors"
	"math"

	"golang.org/x/sys/unix"
)

func availableSpace(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	blocks := int64(stat.F_bavail)
	bsize := int64(stat.F_bsize)
	if blocks < 0 || bsize <= 0 {
		return 0, errors.New("invalid filesystem stats")
	}
	if blocks > math.MaxInt64/bsize {
		return 0, errors.New("available space exceeds int64 max")
	}
	return blocks * bsize, nil
}
