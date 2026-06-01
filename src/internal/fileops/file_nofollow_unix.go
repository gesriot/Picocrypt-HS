//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package fileops

import (
	"os"

	"golang.org/x/sys/unix"
)

func openFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
