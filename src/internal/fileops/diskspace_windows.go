//go:build windows

package fileops

import (
	"errors"
	"math"

	"golang.org/x/sys/windows"
)

func availableSpace(path string) (int64, error) {
	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	err = windows.GetDiskFreeSpaceEx(pathPtr, &freeBytesAvailable, &totalBytes, &totalFreeBytes)
	if err != nil {
		return 0, err
	}
	if freeBytesAvailable > uint64(math.MaxInt64) {
		return 0, errors.New("available space exceeds int64 max")
	}
	return int64(freeBytesAvailable), nil
}
