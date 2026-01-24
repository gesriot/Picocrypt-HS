//go:build windows

package cli

import (
	"golang.org/x/sys/windows"
)

// availableSpace returns available bytes at the given path.
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
	return int64(freeBytesAvailable), nil
}
