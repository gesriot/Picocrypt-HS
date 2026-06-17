package util

import "math"

// SafeUint64ToInt64 returns (value, true) if safe, (0, false) if overflow.
func SafeUint64ToInt64(v uint64) (int64, bool) {
	if v > math.MaxInt64 {
		return 0, false
	}
	return int64(v), true
}
