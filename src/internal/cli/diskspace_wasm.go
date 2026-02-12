//go:build js && wasm

package cli

import "errors"

// availableSpace stub for WASM (unused but needed for build).
func availableSpace(_ string) (int64, error) {
	return 0, errors.New("disk space check not supported in WASM")
}
