//go:build wasm

package fileops

import "errors"

func availableSpace(_ string) (int64, error) {
	return 0, errors.New("disk space check not supported in WASM")
}
