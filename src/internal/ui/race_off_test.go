//go:build !race

package ui

// raceEnabled reports whether the test binary was built with -race.
// Used to skip Fyne-cache-racy tests on the -race-enabled CI matrix
// (the races live in fyne.io/fyne/v2/internal/cache, not in our code).
const raceEnabled = false
