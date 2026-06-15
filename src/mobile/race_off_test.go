//go:build !race

package mobile

// raceEnabled reports whether the test binary was built with -race.
// See race_on_test.go: used to skip the real memory-hard Argon2id KDF round-trip
// only on the -race-enabled CI matrix, where it OOM-kills the hosted runner.
const raceEnabled = false
