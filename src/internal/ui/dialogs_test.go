package ui

import (
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

// TestAboutModalShowsAppVersion pins the GUI's only version indicator: the
// window title carries no version (#133), so the About dialog must show it.
func TestAboutModalShowsAppVersion(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.showAboutModal()
	})

	if a.aboutModal == nil {
		t.Fatal("about modal was not created")
	}
	if a.aboutVersionLabel == nil {
		t.Fatal("about version label was not created")
	}
	if !strings.Contains(a.aboutVersionLabel.Text, a.Version) {
		t.Fatalf("about label %q does not contain version %q", a.aboutVersionLabel.Text, a.Version)
	}
}

// TestBuildUICreatesAboutButton ensures the About entry point is present in
// the header row without growing the fixed-size window.
func TestBuildUICreatesAboutButton(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	if a.aboutButton == nil {
		t.Fatal("buildUI did not create the about button")
	}
}

func TestNormalizeSelectedOutputPathPreservesDots(t *testing.T) {
	got := normalizeSelectedOutputPath("/tmp/report.v2.backup", "encrypt", "input.txt", false, false)
	want := filepath.Join(string(filepath.Separator), "tmp", "report.v2.txt.pcv")
	if got != want {
		t.Fatalf("normalizeSelectedOutputPath(...) = %q, want %q", got, want)
	}
}

func TestShouldShowOverwriteModalSkipsDialogConfirmedOutput(t *testing.T) {
	if showOverwriteModalForOutput(true, false, true) {
		t.Fatal("dialog-confirmed output should not trigger a second overwrite modal")
	}
	if !showOverwriteModalForOutput(true, false, false) {
		t.Fatal("plain existing output should still trigger overwrite modal")
	}
}
