package cli

import (
	"os"
	"testing"
)

// chdirForTest switches into dir and restores the previous working directory
// when the test ends. It stands in for testing.T.Chdir, which needs Go 1.24;
// this fork targets Go 1.20, the last release supporting macOS 10.13.
func chdirForTest(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Errorf("restore cwd %s: %v", prev, err)
		}
	})
}
