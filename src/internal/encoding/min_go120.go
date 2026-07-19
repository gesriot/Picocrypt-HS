package encoding

// min returns the smaller of a and b. Go 1.20, the last release supporting
// macOS 10.13, has no builtin min; this declaration shadows it on newer
// toolchains so the call sites stay identical to upstream.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
