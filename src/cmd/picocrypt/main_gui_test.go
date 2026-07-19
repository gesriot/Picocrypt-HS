//go:build !cli

package main

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2/test"
)

func TestFatalErrorDialogQuitsWhenDismissed(t *testing.T) {
	app := test.NewApp()
	t.Cleanup(app.Quit)

	win := app.NewWindow("Picocrypt NG")
	closed := make(chan struct{}, 1)
	d := newFatalErrorDialog(errors.New("startup failed"), win, func() {
		closed <- struct{}{}
	})

	d.Show()
	d.Dismiss()

	select {
	case <-closed:
	default:
		t.Fatal("fatal error dialog close did not run quit callback")
	}
}
