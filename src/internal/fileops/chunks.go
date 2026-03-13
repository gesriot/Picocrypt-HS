package fileops

import (
	"path/filepath"
	"regexp"
)

var splitChunkRE = regexp.MustCompile(`(?i)\.pcv\.[0-9]+$`)

// IsSplitChunkPath reports whether path names a numbered split-volume chunk.
func IsSplitChunkPath(path string) bool {
	return splitChunkRE.MatchString(filepath.Base(path))
}

// SplitChunkBase returns the base .pcv path for a numbered split-volume chunk.
func SplitChunkBase(path string) (string, bool) {
	if !IsSplitChunkPath(path) {
		return "", false
	}

	idx := splitChunkRE.FindStringIndex(path)
	if idx == nil {
		return "", false
	}
	return path[:idx[0]+4], true
}
