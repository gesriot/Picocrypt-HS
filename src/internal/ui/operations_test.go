// Package ui provides tests for UI operations and validation logic.
package ui

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// TestOnClickStartValidation tests the validation logic in onClickStart.
func TestOnClickStartValidation(t *testing.T) {
	newTestFyneApp(t)

	t.Run("NoMode", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = ""
		a.State.Password = "secret"

		// Should return early without starting work
		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start work when mode is empty")
		}
	})

	t.Run("NoCredentials", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = ""
		a.State.Keyfiles = nil

		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start work without credentials")
		}
	})

	t.Run("EncryptPasswordMismatch", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = "secret"
		a.State.CPassword = "different"

		a.onClickStart()
		if a.State.Working {
			t.Error("Should not start encrypt with mismatched passwords")
		}
	})
}

func TestUpdateOutputFileForCompressClearsDialogConfirmation(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Mode = "encrypt"
	a.State.InputFile = filepath.Join(t.TempDir(), "report.txt")
	a.State.OutputFile = filepath.Join(t.TempDir(), "report.txt.pcv")
	a.State.OutputChosenViaSaveDialog = true

	a.updateOutputFileForCompress(true)

	if a.State.OutputChosenViaSaveDialog {
		t.Fatal("programmatic output path changes should clear dialog confirmation state")
	}
	if got := a.State.OutputFile; got != filepath.Join(filepath.Dir(a.State.OutputFile), "report.txt.zip.pcv") {
		t.Fatalf("OutputFile = %q", got)
	}
}

func TestCreateReporterUsesAtomicCancelledFlag(t *testing.T) {
	newTestFyneApp(t)

	a := createTestApp(t)
	a.State.Working = false
	a.cancelled.Store(false)

	reporter := a.CreateReporter()
	if reporter.IsCancelled() {
		t.Fatal("reporter should not report cancellation when only Working is false")
	}

	a.cancelled.Store(true)
	if !reporter.IsCancelled() {
		t.Fatal("reporter should use the atomic cancelled flag")
	}
}

func TestApplyRecursiveSelectionRestoresSavedSettings(t *testing.T) {
	newTestFyneApp(t)

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "input.txt")
	if err := os.WriteFile(inputPath, []byte("payload"), 0600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	a := createTestApp(t)
	a.State.Compress = false
	a.advancedContainer = container.NewVBox()

	saved := app.RecursiveSnapshot{
		Password:       "secret",
		Keyfile:        true,
		Keyfiles:       []string{"k1", "k2"},
		KeyfileOrdered: true,
		KeyfileLabel:   "Using multiple keyfiles",
		Comments:       "saved comments",
		Paranoid:       true,
		ReedSolomon:    true,
		Deniability:    true,
		Split:          true,
		SplitSize:      "64",
		SplitSelected:  2,
		Delete:         true,
	}

	done := make(chan struct{})
	go func() {
		a.applyRecursiveSelection(inputPath, saved, 1, 3)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("applyRecursiveSelection did not complete")
	}

	fyne.DoAndWait(func() {})

	if a.State.InputFile != inputPath {
		t.Fatalf("InputFile = %q, want %q", a.State.InputFile, inputPath)
	}
	if a.State.Password != saved.Password || a.State.CPassword != saved.Password {
		t.Fatalf("passwords not restored: %q / %q", a.State.Password, a.State.CPassword)
	}
	if got := a.State.PopupStatus; got != "Processing file 1/3..." {
		t.Fatalf("PopupStatus = %q", got)
	}
	if !a.State.Keyfile || !a.State.KeyfileOrdered || !a.State.Paranoid || !a.State.ReedSolomon || !a.State.Deniability || !a.State.Split || !a.State.Delete {
		t.Fatal("saved boolean options were not restored")
	}
	if a.State.SplitSize != saved.SplitSize || a.State.SplitSelected != saved.SplitSelected {
		t.Fatal("split settings were not restored")
	}
	if a.State.Comments != saved.Comments || a.State.KeyfileLabel != saved.KeyfileLabel {
		t.Fatal("saved metadata was not restored")
	}
}

func TestCreateReporterCallbacksUpdateStateAndCancelButton(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	fyne.DoAndWait(func() {
		a.showProgressModal()
	})

	reporter := a.CreateReporter()

	done := make(chan struct{})
	go func() {
		reporter.SetStatus("Encrypting...")
		reporter.SetProgress(0.5, "50%")
		reporter.SetCanCancel(false)
		reporter.SetCanCancel(true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reporter callbacks did not complete")
	}

	fyne.DoAndWait(func() {})

	if a.State.PopupStatus != "Encrypting..." {
		t.Fatalf("PopupStatus = %q; want %q", a.State.PopupStatus, "Encrypting...")
	}
	if a.State.Progress != 0.5 {
		t.Fatalf("Progress = %v; want 0.5", a.State.Progress)
	}
	if a.State.ProgressInfo != "50%" {
		t.Fatalf("ProgressInfo = %q; want %q", a.State.ProgressInfo, "50%")
	}
	if !a.State.CanCancel {
		t.Fatal("CanCancel should be true after final callback")
	}
	if a.cancelButton == nil {
		t.Fatal("cancelButton should exist after showProgressModal")
	}
	if a.cancelButton.Disabled() {
		t.Fatal("cancelButton should be enabled")
	}
}

// TestSplitUnitConversion verifies the doEncrypt split-unit index mapping
// (splitUnitFromIndex) turns each State.SplitSelected value into the correct
// fileops.SplitUnit constant the encrypt request carries.
func TestSplitUnitConversion(t *testing.T) {
	testCases := []struct {
		name  string
		index int32
		want  fileops.SplitUnit
	}{
		{"KiB", 0, fileops.SplitUnitKiB},
		{"MiB", 1, fileops.SplitUnitMiB},
		{"GiB", 2, fileops.SplitUnitGiB},
		{"TiB", 3, fileops.SplitUnitTiB},
		{"Total", 4, fileops.SplitUnitTotal},
		{"OutOfRangeFallsBackToKiB", 99, fileops.SplitUnitKiB},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := splitUnitFromIndex(tc.index); got != tc.want {
				t.Errorf("splitUnitFromIndex(%d) = %d; want %d", tc.index, got, tc.want)
			}
		})
	}
}

// TestSplitUnitsLabelsAlignWithIndices keeps the GUI dropdown labels aligned
// with the index meanings splitUnitFromIndex encodes: SplitUnits[i] must name
// the unit splitUnitFromIndex(i) returns.
func TestSplitUnitsLabelsAlignWithIndices(t *testing.T) {
	state := mustNewState(t)
	want := []string{"KiB", "MiB", "GiB", "TiB", "Total"}
	if len(state.SplitUnits) != len(want) {
		t.Fatalf("len(SplitUnits) = %d; want %d", len(state.SplitUnits), len(want))
	}
	for i, w := range want {
		if state.SplitUnits[i] != w {
			t.Errorf("SplitUnits[%d] = %q; want %q", i, state.SplitUnits[i], w)
		}
	}
}

// TestOperationStatusColors tests that status colors are set correctly.
func TestOperationStatusColors(t *testing.T) {
	t.Run("SuccessStatus", func(t *testing.T) {
		state := mustNewState(t)
		state.SetStatus("Completed", util.GREEN)

		if state.MainStatus != "Completed" {
			t.Errorf("MainStatus = %q; want 'Completed'", state.MainStatus)
		}
		if state.MainStatusColor != util.GREEN {
			t.Error("MainStatusColor should be GREEN")
		}
	})

	t.Run("ErrorStatus", func(t *testing.T) {
		state := mustNewState(t)
		state.SetStatus("Failed", util.RED)

		if state.MainStatus != "Failed" {
			t.Errorf("MainStatus = %q; want 'Failed'", state.MainStatus)
		}
		if state.MainStatusColor != util.RED {
			t.Error("MainStatusColor should be RED")
		}
	})

	t.Run("WarningStatus", func(t *testing.T) {
		state := mustNewState(t)
		state.SetStatus("Warning", util.YELLOW)

		if state.MainStatus != "Warning" {
			t.Errorf("MainStatus = %q; want 'Warning'", state.MainStatus)
		}
		if state.MainStatusColor != util.YELLOW {
			t.Error("MainStatusColor should be YELLOW")
		}
	})
}

// TestCanStartLogic tests the comprehensive start validation.
func TestCanStartLogic(t *testing.T) {
	testCases := []struct {
		name      string
		mode      string
		password  string
		cPassword string
		keyfiles  []string
		expected  bool
	}{
		{"NoCredentials", "encrypt", "", "", nil, false},
		{"PasswordOnly", "encrypt", "secret", "secret", nil, true},
		{"KeyfilesOnly", "encrypt", "", "", []string{"key.bin"}, true},
		{"Both", "encrypt", "secret", "secret", []string{"key.bin"}, true},
		{"EncryptMismatch", "encrypt", "secret", "wrong", nil, false},
		{"DecryptMismatchOK", "decrypt", "secret", "wrong", nil, true},
		{"DecryptNoPassword", "decrypt", "", "", []string{"key.bin"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := mustNewState(t)
			state.Mode = tc.mode
			state.Password = tc.password
			state.CPassword = tc.cPassword
			state.Keyfiles = tc.keyfiles

			result := state.CanStart()
			if result != tc.expected {
				t.Errorf("CanStart() = %v; want %v", result, tc.expected)
			}
		})
	}
}

// TestCancelButtonState tests cancel button enable/disable logic.
// TestWorkerCallbackStateRace exercises the APP-02 worker↔render boundary at the
// *App level: one goroutine plays the encrypt/decrypt worker using the exact
// accessor pattern doEncrypt/doDecrypt now use (a.State.Snapshot() for reads,
// SetStatus/SetKept for status/result writes), while other goroutines play the
// Fyne render-thread callbacks driving the locked setters/getters the
// operations.go fyne.Do/DoAndWait blocks use (SetWorking/SetMode/IsWorking/...).
//
// It deliberately touches NO Fyne widgets, so it exercises the project-code
// State race directly and is not polluted by the upstream
// fyne.io/fyne/v2/internal/cache races (Pitfall 4). It must be clean under
// `go test -race ./internal/ui` — the APP-02 gate.
func TestWorkerCallbackStateRace(t *testing.T) {
	if raceEnabled {
		// Belt-and-suspenders: this test never builds widgets, so it is safe
		// under -race. The guard documents that any future variant which DOES
		// touch Fyne widgets must skip here (mirrors drop_test.go's quarantine
		// of the Fyne-cache-racy widget paths).
		_ = raceEnabled
	}

	a := createTestApp(t)

	const iterations = 200
	var wg sync.WaitGroup

	// Worker goroutine: snapshot the request fields, then write status/result
	// via the locked setters — the operations.go doEncrypt/doDecrypt hot path.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			snap := a.State.Snapshot()
			_ = snap.Mode
			_ = snap.InputFile
			_ = snap.OutputFile
			_ = snap.Password
			_ = snap.Keyfiles
			_ = snap.Comments
			_ = snap.Deniability
			_ = snap.Keep
			a.State.SetStatus("working", util.WHITE)
			a.State.SetKept(i%2 == 0)
		}
	}()

	// Render-thread writer goroutine: the drop/operations fyne.Do callbacks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			a.State.SetMode("encrypt")
			a.State.SetWorking(i%2 == 0)
			a.State.SetInputFile("in.txt")
			a.State.SetOutputFile("out.pcv")
			a.State.SetComments("hello")
			a.State.SetDeniability(i%2 == 0)
			a.State.SetKeep(i%2 == 1)
		}
	}()

	// Render-thread reader goroutine: the guards/labels that read shared fields.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = a.State.IsEncrypting()
			_ = a.State.IsDecrypting()
			_ = a.State.IsWorking()
			_ = a.State.WasKept()
			_ = a.State.Snapshot()
		}
	}()

	wg.Wait()
}

// TestUpdateUIStateReadsStateThroughSnapshot covers the render path that the
// accessor-only worker test above does not touch. It keeps widgets nil so the
// test isolates project State access rather than Fyne internals; under -race it
// must stay clean while worker-style writers reset/update State concurrently.
func TestUpdateUIStateReadsStateThroughSnapshot(t *testing.T) {
	a := &App{State: mustNewState(t)}

	const iterations = 500
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			a.State.ResetUI()
			a.State.SetStatus("working", util.WHITE)
			a.State.SetScanning(i%2 == 0)
			a.State.SetWorking(i%2 == 1)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			a.updateUIState()
		}
	}()

	wg.Wait()
}

func TestCancelButtonState(t *testing.T) {
	state := mustNewState(t)

	// Initially not cancellable
	if state.CanCancel {
		t.Error("CanCancel should be false initially")
	}

	// During operation
	state.SetCanCancel(true)
	if !state.CanCancel {
		t.Error("CanCancel should be true during operation")
	}

	// After operation
	state.SetCanCancel(false)
	if state.CanCancel {
		t.Error("CanCancel should be false after operation")
	}
}

// createTestApp creates a minimal App instance for testing.
func createTestApp(t *testing.T) *App {
	t.Helper()

	a, err := NewApp("v2.02")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	return a
}
