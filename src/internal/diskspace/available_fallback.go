//go:build !(darwin || linux || freebsd || dragonfly || openbsd || windows)

package diskspace

import "errors"

// Available is a stub for platforms without a free-space probe — js/wasm and
// any GOOS we don't implement a real probe for (e.g. netbsd/solaris, which
// need Statvfs rather than Statfs). Callers treat the error as "unknown space".
func Available(_ string) (int64, error) {
	return 0, errors.New("disk space check not supported on this platform")
}
