//go:build !unix

package fileops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// rootDir is the non-unix fallback for the os.Root stand-in described in
// root_unix.go. Without openat(2) it validates the joined path stays under the
// root instead of holding the directory open, which is what this code did
// before upstream adopted os.Root. That is weaker against a directory swapped
// mid-extraction; this fork targets macOS 10.13, where the unix
// implementation is the one that runs.
type rootDir struct {
	name string
}

func openRoot(dir string) (*rootDir, error) {
	resolved, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", resolved)
	}
	return &rootDir{name: resolved}, nil
}

func (r *rootDir) Close() error { return nil }

// resolve joins name onto the root and rejects anything that escapes it.
func (r *rootDir) resolve(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("absolute path %q escapes root", name)
	}
	joined := filepath.Clean(filepath.Join(r.name, filepath.FromSlash(name)))
	if joined != r.name && !strings.HasPrefix(joined, r.name+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes root", name)
	}
	return joined, nil
}

func (r *rootDir) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	path, err := r.resolve(name)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

func (r *rootDir) Remove(name string) error {
	path, err := r.resolve(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}
