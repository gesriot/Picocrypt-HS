//go:build windows

package fileops

import (
	"os"

	"golang.org/x/sys/windows"
)

func openFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	if path == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_FILE_NOT_FOUND}
	}
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var access uint32
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		access = windows.GENERIC_READ
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_CREATE != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA
	}
	access |= windows.FILE_READ_ATTRIBUTES

	var createMode uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == (os.O_CREATE | os.O_EXCL):
		createMode = windows.CREATE_NEW
	case flag&os.O_CREATE != 0:
		createMode = windows.OPEN_ALWAYS
	default:
		createMode = windows.OPEN_EXISTING
	}

	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if perm.Perm()&0200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_FLAG_OPEN_REPARSE_POINT
	}

	h, err := windows.CreateFile(
		pathp,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		createMode,
		attrs,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		_ = windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_CANT_ACCESS_FILE}
	}
	if flag&os.O_TRUNC != 0 {
		if _, err := windows.Seek(h, 0, 0); err != nil {
			_ = windows.CloseHandle(h)
			return nil, &os.PathError{Op: "truncate", Path: path, Err: err}
		}
		if err := windows.SetEndOfFile(h); err != nil {
			_ = windows.CloseHandle(h)
			return nil, &os.PathError{Op: "truncate", Path: path, Err: err}
		}
	}

	return os.NewFile(uintptr(h), path), nil
}
