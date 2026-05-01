//go:build race

package ui

// raceEnabled reports whether the test binary was built with -race.
// True under `go test -race`; lets us skip Fyne-cache-racy tests on
// the -race CI matrix (the races live in fyne.io/fyne/v2/internal/cache,
// not in our code). The same tests still run on the no-race matrix.
const raceEnabled = true
