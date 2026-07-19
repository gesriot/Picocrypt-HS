package app

import "testing"

func TestUIReporterForwardsCompleteCallbackContract(t *testing.T) {
	var gotStatus string
	var gotFraction float32
	var gotInfo string
	var gotCanCancel bool
	cancelled := false

	reporter := NewUIReporter(
		func(text string) { gotStatus = text },
		func(fraction float32, info string) {
			gotFraction = fraction
			gotInfo = info
		},
		func(can bool) { gotCanCancel = can },
		func() bool { return cancelled },
	)

	reporter.SetStatus("Encrypting...")
	reporter.SetProgress(0.5, "50%")
	reporter.SetCanCancel(true)

	if gotStatus != "Encrypting..." {
		t.Fatalf("status callback = %q; want %q", gotStatus, "Encrypting...")
	}
	if gotFraction != 0.5 || gotInfo != "50%" {
		t.Fatalf("progress callback = (%v, %q); want (0.5, %q)", gotFraction, gotInfo, "50%")
	}
	if !gotCanCancel {
		t.Fatal("cancellability callback did not receive true")
	}
	if reporter.IsCancelled() {
		t.Fatal("reporter reported cancellation before its operation context was cancelled")
	}
	cancelled = true
	if !reporter.IsCancelled() {
		t.Fatal("reporter did not forward context-backed cancellation")
	}
}
