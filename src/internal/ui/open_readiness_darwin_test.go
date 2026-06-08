//go:build darwin

package ui

import "testing"

func TestDarwinReadinessStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		code int
		want openedPathReadinessState
	}{
		{name: "ready", code: pcngOpenedPathReady, want: openedPathReady},
		{name: "downloading", code: pcngOpenedPathDownloading, want: openedPathPending},
		{name: "not downloaded", code: pcngOpenedPathNotDownloaded, want: openedPathPending},
		{name: "stale downloaded", code: pcngOpenedPathStale, want: openedPathPending},
		{name: "missing", code: pcngOpenedPathMissing, want: openedPathMissing},
		{name: "error", code: pcngOpenedPathError, want: openedPathError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := openedPathStateFromDarwinCode(tc.code)
			if got != tc.want {
				t.Fatalf("openedPathStateFromDarwinCode(%d) = %v; want %v", tc.code, got, tc.want)
			}
		})
	}
}
