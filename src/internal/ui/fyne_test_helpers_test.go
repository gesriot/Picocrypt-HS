package ui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

func newTestFyneApp(t *testing.T) fyne.App {
	t.Helper()

	app := test.NewApp()
	t.Cleanup(func() {
		fyne.DoAndWait(func() {})
		app.Quit()
	})
	return app
}
