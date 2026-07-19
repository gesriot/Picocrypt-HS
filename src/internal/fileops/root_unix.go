//go:build unix

package fileops

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// rootDir is a minimal stand-in for *os.Root, which is only available from Go
// 1.24 onward; this fork targets Go 1.20, the last release supporting macOS
// 10.13. It provides the subset used by archive extraction: OpenFile, Remove
// and Close.
//
// Confinement works the same way as os.Root: the directory is held open and
// every path component is traversed with openat(2) relative to that descriptor,
// so a component swapped for a symlink or a parent directory moved mid-run
// cannot redirect a write outside the root. This shim is stricter than os.Root
// in one respect — O_NOFOLLOW is applied to every component, so symlinks are
// rejected outright rather than accepted when they resolve back inside the
// root. Archive entries that are symlinks are already rejected before reaching
// here, so the stricter rule costs nothing.
type rootDir struct {
	dir  *os.File
	name string
}

// openRoot opens dir as a confinement root. It mirrors os.OpenRoot.
func openRoot(dir string) (*rootDir, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &rootDir{dir: f, name: dir}, nil
}

func (r *rootDir) Close() error {
	return r.dir.Close()
}

// splitPath validates name as a root-relative path and splits it into the
// leading directory components and the final element.
func splitPath(name string) ([]string, string, error) {
	if name == "" {
		return nil, "", fmt.Errorf("empty path")
	}
	if strings.HasPrefix(name, "/") {
		return nil, "", fmt.Errorf("absolute path %q escapes root", name)
	}
	parts := strings.Split(name, "/")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		switch p {
		case "", ".":
			// Skip no-op components; "a//b" and "a/./b" mean "a/b".
		case "..":
			return nil, "", fmt.Errorf("path %q escapes root", name)
		default:
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) == 0 {
		return nil, "", fmt.Errorf("path %q has no final element", name)
	}
	return cleaned[:len(cleaned)-1], cleaned[len(cleaned)-1], nil
}

// openParent walks dirs from the root descriptor, returning a descriptor for
// the final directory along with a closer. The returned descriptor is only
// valid until the closer runs.
func (r *rootDir) openParent(dirs []string) (int, func(), error) {
	fd := int(r.dir.Fd())
	closer := func() {}
	for _, d := range dirs {
		next, err := unix.Openat(fd, d, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			closer()
			return -1, nil, fmt.Errorf("open directory %s: %w", d, err)
		}
		prev := closer
		closer = func() {
			_ = unix.Close(next)
			prev()
		}
		fd = next
	}
	return fd, closer, nil
}

// OpenFile opens name relative to the root, mirroring os.Root.OpenFile.
func (r *rootDir) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	dirs, base, err := splitPath(name)
	if err != nil {
		return nil, err
	}
	parent, closeParents, err := r.openParent(dirs)
	if err != nil {
		return nil, err
	}
	defer closeParents()

	fd, err := unix.Openat(parent, base, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), r.name+"/"+name), nil
}

// Remove deletes name relative to the root, mirroring os.Root.Remove.
func (r *rootDir) Remove(name string) error {
	dirs, base, err := splitPath(name)
	if err != nil {
		return err
	}
	parent, closeParents, err := r.openParent(dirs)
	if err != nil {
		return err
	}
	defer closeParents()

	return unix.Unlinkat(parent, base, 0)
}
