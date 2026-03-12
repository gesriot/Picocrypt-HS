package ui

import (
	"path/filepath"
	"testing"
)

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
