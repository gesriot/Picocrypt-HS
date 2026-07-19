package diskspace

import (
	"path/filepath"
	"testing"
)

func TestAvailable(t *testing.T) {
	space, err := Available(t.TempDir())
	if err != nil {
		t.Fatalf("Available() error = %v", err)
	}
	// The exact byte count is filesystem- and host-dependent and cannot be
	// asserted portably. ">0 && err==nil" is the strongest portable claim: a
	// mounted, writable temp dir always has some free space, and the int64
	// overflow guards in Available guarantee the result is non-negative (it
	// returns an error instead of wrapping). So a positive value proves the
	// happy path computed a sane figure rather than silently returning 0.
	if space <= 0 {
		t.Errorf("Available() = %d, want > 0", space)
	}
}

func TestAvailableNonExistentPath(t *testing.T) {
	// Derive a guaranteed-absent path under a fresh temp dir instead of a
	// hardcoded "/nonexistent": the latter could in principle exist on some host
	// and would mask a regression. The parent temp dir exists but these nested
	// components do not, so Statfs must fail. Mutation caught: Available
	// swallowing the Statfs error for a missing path and returning (0, nil).
	missing := filepath.Join(t.TempDir(), "definitely", "absent")
	if _, err := Available(missing); err == nil {
		t.Errorf("Available(%q) on non-existent path: expected error, got nil", missing)
	}
}
