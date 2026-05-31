package ui

import (
	"os"
	"testing"

	"Picocrypt-NG/internal/app"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// mustNewState builds an *app.State for UI tests, failing the test if RS-codec
// initialization returns an error. Centralizes the (*State, error) call after
// APP-01 changed app.NewState's signature, keeping the many call sites terse.
func mustNewState(t *testing.T) *app.State {
	t.Helper()
	s, err := app.NewState()
	if err != nil {
		t.Fatalf("app.NewState() returned error: %v", err)
	}
	return s
}

// TestMain pre-warms Fyne's process-global font-metric cache before any
// parallel test goroutines start. Fyne v2.7.3's internal/cache/base.go
// `setAlive` is racy on first writes (verified via -race detector during
// concurrent test.NewApp + MeasureText calls), and the cache is shared
// across all test.NewApp instances. Running one MeasureText in TestMain
// populates the cache serially, so subsequent parallel tests only read.
func TestMain(m *testing.M) {
	app := test.NewApp()
	fyne.DoAndWait(func() {
		// Trigger font metric cache population on the common path.
		_ = fyne.MeasureText("Picocrypt NG 2.09", 14, fyne.TextStyle{})
		_ = fyne.MeasureText("Picocrypt NG 2.09", 14, fyne.TextStyle{Bold: true})
	})
	app.Quit()
	os.Exit(m.Run())
}

func newTestFyneApp(t *testing.T) fyne.App {
	t.Helper()

	app := test.NewApp()
	t.Cleanup(func() {
		fyne.DoAndWait(func() {})
		app.Quit()
	})
	return app
}
