//go:build wasm

package fileops

import (
	"errors"
	"os"
)

func openFileNoFollow(path string, _ int, _ os.FileMode) (*os.File, error) {
	return nil, &os.PathError{Op: "open", Path: path, Err: errors.ErrUnsupported}
}
