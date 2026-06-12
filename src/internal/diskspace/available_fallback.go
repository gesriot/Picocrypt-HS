//go:build !(darwin || dragonfly || freebsd || linux || netbsd || solaris || windows || openbsd)

package diskspace

import "errors"

// Available is a stub for platforms without a free-space probe (e.g. js/wasm).
func Available(_ string) (int64, error) {
	return 0, errors.New("disk space check not supported on this platform")
}
