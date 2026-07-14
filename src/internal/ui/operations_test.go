// Package ui provides tests for UI operations and validation logic.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

type controlledOperationCall struct {
	ctx      context.Context
	input    operationInput
	reporter volume.ProgressReporter
}

type controlledOperationExecutor struct {
	calls   chan controlledOperationCall
	results chan operationResult
}

func newControlledOperationExecutor() *controlledOperationExecutor {
	return &controlledOperationExecutor{
		calls:   make(chan controlledOperationCall, 4),
		results: make(chan operationResult, 4),
	}
}

func (e *controlledOperationExecutor) execute(ctx context.Context, input operationInput, reporter volume.ProgressReporter) operationResult {
	e.calls <- controlledOperationCall{ctx: ctx, input: input, reporter: reporter}
	return <-e.results
}

func waitForControlledOperation(t *testing.T, calls <-chan controlledOperationCall) controlledOperationCall {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(2 * time.Second):
		t.Fatal("operation executor was not called")
		return controlledOperationCall{}
	}
}

func drainOperationFinalizer(t *testing.T, a *App) {
	t.Helper()
	a.workers.wait()
	fyne.DoAndWait(func() {})
}

func requireZeroedPassword(t *testing.T, password []byte) {
	t.Helper()
	for i, value := range password {
		if value != 0 {
			t.Fatalf("owned operation password byte %d was not zeroed after executor return", i)
		}
	}
}

func TestCancelOperationRejectsLateProgressUntilWorkerFinalizes(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	executor := newControlledOperationExecutor()
	a.operationExecutor = executor.execute

	inputPath := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(inputPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	fyne.DoAndWait(func() {
		a.onDrop([]string{inputPath})
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.startWork()
	})
	call := waitForControlledOperation(t, executor.calls)

	call.reporter.SetStatus("before cancellation")
	call.reporter.SetProgress(0.25, "25%")
	call.reporter.SetCanCancel(true)
	fyne.DoAndWait(func() {
		a.cancelButton.OnTapped()
	})

	select {
	case <-call.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("cancel button did not cancel the operation context")
	}

	cancelledState := a.State.UISnapshot()
	cancelledProgress := a.State.Progress
	cancelledProgressInfo := a.State.ProgressInfo
	cancelledCanCancel := a.State.CanCancel
	cancelledBoundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read status binding after cancel: %v", err)
	}
	cancelledBoundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read progress binding after cancel: %v", err)
	}

	call.reporter.SetStatus("late update")
	call.reporter.SetProgress(0.9, "90%")
	call.reporter.SetCanCancel(true)
	fyne.DoAndWait(func() {})

	got := a.State.UISnapshot()
	if got.Status.Kind != app.StatusCancelledByUser || !got.Working {
		t.Fatalf("state after cancel = status %v, working %v; want semantic cancellation while worker remains active", got.Status.Kind, got.Working)
	}
	if got.Status != cancelledState.Status || got.PopupStatus != cancelledState.PopupStatus {
		t.Fatalf("late reporter status changed cancelled state: before=%+v/%+v after=%+v/%+v", cancelledState.Status, cancelledState.PopupStatus, got.Status, got.PopupStatus)
	}
	if a.State.Progress != cancelledProgress || a.State.ProgressInfo != cancelledProgressInfo {
		t.Fatalf("late reporter progress changed state: before=%v/%q after=%v/%q", cancelledProgress, cancelledProgressInfo, a.State.Progress, a.State.ProgressInfo)
	}
	if cancelledCanCancel || a.State.CanCancel {
		t.Fatalf("CanCancel after cancel/late callback = %v/%v; want false throughout", cancelledCanCancel, a.State.CanCancel)
	}
	if !a.cancelButton.Disabled() {
		t.Fatal("cancel button remained enabled after cancellation")
	}
	boundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read status binding: %v", err)
	}
	if boundStatus != cancelledBoundStatus {
		t.Fatalf("late reporter status replaced cancellation binding: before=%q after=%q", cancelledBoundStatus, boundStatus)
	}
	boundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read progress binding: %v", err)
	}
	if boundProgress != cancelledBoundProgress {
		t.Fatalf("late reporter progress replaced cancellation binding: before=%v after=%v", cancelledBoundProgress, boundProgress)
	}

	executor.results <- operationResult{completed: true}
	drainOperationFinalizer(t, a)
	finalState := a.State.UISnapshot()
	if finalState.Status.Kind != app.StatusCancelledByUser {
		t.Fatalf("final status after cancelled executor returned success = %v; want semantic cancellation", finalState.Status.Kind)
	}
	finalBoundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read final status binding: %v", err)
	}
	if finalBoundStatus != cancelledBoundStatus {
		t.Fatalf("finalizer replaced cancellation binding: before=%q after=%q", cancelledBoundStatus, finalBoundStatus)
	}
	if finalState.Working {
		t.Fatal("Working remained true after the controlled executor finalized")
	}
	if finalState.ShowProgress {
		t.Fatal("progress modal state remained visible after finalization")
	}
	if overlays := a.Window.Canvas().Overlays().List(); len(overlays) != 0 {
		t.Fatalf("progress modal overlay count = %d; want hidden", len(overlays))
	}
}

func TestOperationInputPreservesSelectedVolumeOptions(t *testing.T) {
	t.Run("encrypt", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		executor := newControlledOperationExecutor()
		a.operationExecutor = executor.execute

		files := []string{"first.txt", "second.txt"}
		onlyFiles := []string{"first.txt"}
		folders := []string{"folder"}
		keyfiles := []string{"key-b", "key-a"}
		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = "input.zip"
			a.State.OutputFile = "output.pcv"
			a.State.AllFiles = files
			a.State.OnlyFiles = onlyFiles
			a.State.OnlyFolders = folders
			a.State.Password = "owned password"
			a.State.CPassword = "owned password"
			a.State.Keyfiles = keyfiles
			a.State.KeyfileOrdered = true
			a.State.Comments = "public comment"
			a.State.Paranoid = true
			a.State.ReedSolomon = true
			a.State.Deniability = true
			a.State.Compress = true
			a.State.Split = true
			a.State.SplitSize = "7"
			a.State.SplitSelected = 3
			a.State.Delete = true
			a.startWork()
		})

		call := waitForControlledOperation(t, executor.calls)
		fyne.DoAndWait(func() {
			a.State.Password = "changed"
			a.State.AllFiles[0] = "changed-file"
			a.State.OnlyFiles[0] = "changed-direct-file"
			a.State.OnlyFolders[0] = "changed-folder"
			a.State.Keyfiles[0] = "changed-key"
		})

		got := call.input
		if got.mode != "encrypt" || got.inputFile != "input.zip" || got.outputFile != "output.pcv" {
			t.Fatalf("encrypt paths/mode = (%q, %q, %q)", got.mode, got.inputFile, got.outputFile)
		}
		if !reflect.DeepEqual(got.inputFiles, []string{"first.txt", "second.txt"}) ||
			!reflect.DeepEqual(got.onlyFiles, []string{"first.txt"}) ||
			!reflect.DeepEqual(got.onlyFolders, []string{"folder"}) {
			t.Fatalf("owned selections changed: all=%v files=%v folders=%v", got.inputFiles, got.onlyFiles, got.onlyFolders)
		}
		if string(got.password) != "owned password" || !reflect.DeepEqual(got.keyfiles, []string{"key-b", "key-a"}) || !got.keyfileOrdered {
			t.Fatalf("owned credentials changed: password=%q keyfiles=%v ordered=%v", got.password, got.keyfiles, got.keyfileOrdered)
		}
		if got.comments != "public comment" || !got.paranoid || !got.reedSolomon || !got.deniability || !got.compress {
			t.Fatalf("encrypt options were not preserved: %+v", got)
		}
		if !got.split || got.chunkSize != 7 || got.chunkUnit != fileops.SplitUnitTiB || !got.delete {
			t.Fatalf("split/delete options were not preserved: split=%v size=%d unit=%v delete=%v", got.split, got.chunkSize, got.chunkUnit, got.delete)
		}
		if got.rsCodecs != a.rsCodecs {
			t.Fatal("operation input did not preserve the initialized Reed-Solomon codecs")
		}

		executor.results <- operationResult{err: errors.New("controlled stop")}
		drainOperationFinalizer(t, a)
		requireZeroedPassword(t, got.password)
	})

	t.Run("decrypt", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		executor := newControlledOperationExecutor()
		a.operationExecutor = executor.execute

		keyfiles := []string{"key-2", "key-1"}
		fyne.DoAndWait(func() {
			a.State.Mode = "decrypt"
			a.State.InputFile = "volume.pcv"
			a.State.OutputFile = "plain.txt"
			a.State.OnlyFiles = []string{"volume.pcv"}
			a.State.AllFiles = []string{"volume.pcv"}
			a.State.Password = "decrypt password"
			a.State.Keyfiles = keyfiles
			a.State.Keep = true
			a.State.VerifyFirst = true
			a.State.AutoUnzip = true
			a.State.SameLevel = true
			a.State.Recombine = true
			a.State.Deniability = true
			a.State.Delete = true
			// Split is an encrypt-only option. A stale recursive split value must
			// never reject or alter a decrypt request.
			a.State.Split = true
			a.State.SplitSize = "irrelevant to decrypt"
			a.startWork()
		})

		call := waitForControlledOperation(t, executor.calls)
		fyne.DoAndWait(func() {
			a.State.Password = "changed"
			a.State.Keyfiles[0] = "changed-key"
			a.State.AllFiles[0] = "changed-volume"
		})

		got := call.input
		if got.mode != "decrypt" || got.inputFile != "volume.pcv" || got.outputFile != "plain.txt" {
			t.Fatalf("decrypt paths/mode = (%q, %q, %q)", got.mode, got.inputFile, got.outputFile)
		}
		if string(got.password) != "decrypt password" || !reflect.DeepEqual(got.keyfiles, []string{"key-2", "key-1"}) {
			t.Fatalf("decrypt credentials changed: password=%q keyfiles=%v", got.password, got.keyfiles)
		}
		if !got.forceDecrypt || !got.verifyFirst || !got.autoUnzip || !got.sameLevel || !got.recombine || !got.deniability || !got.delete {
			t.Fatalf("decrypt options were not preserved: %+v", got)
		}
		if got.rsCodecs != a.rsCodecs {
			t.Fatal("decrypt input did not preserve the initialized Reed-Solomon codecs")
		}

		executor.results <- operationResult{err: errors.New("controlled stop")}
		drainOperationFinalizer(t, a)
		requireZeroedPassword(t, got.password)
	})
}

func TestCancelAfterSuccessfulOperationPreservesSource(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
		return operationResult{completed: true}
	}
	type cleanupObservation struct {
		ctx       context.Context
		inputFile string
		recursive bool
	}
	cleanupEntered := make(chan cleanupObservation, 1)
	releaseCleanup := make(chan struct{})
	a.operationSourceRemover = func(ctx context.Context, path string, recursive bool) error {
		cleanupEntered <- cleanupObservation{ctx: ctx, inputFile: path, recursive: recursive}
		<-releaseCleanup
		return removeOperationSource(ctx, path, recursive)
	}

	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		a.State.InputFile = source
		a.State.OutputFile = source + ".pcv"
		a.State.OnlyFiles = []string{source}
		a.State.AllFiles = []string{source}
		a.State.Password = "secret"
		a.State.CPassword = "secret"
		a.State.Delete = true
		a.startWork()
	})

	var observed cleanupObservation
	select {
	case observed = <-cleanupEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("successful executor did not reach the production cleanup boundary")
	}
	if observed.inputFile != source || observed.recursive {
		t.Fatalf("cleanup boundary = path %q recursive %v; want single-file removal for %q", observed.inputFile, observed.recursive, source)
	}
	if observed.ctx.Err() != nil {
		t.Fatalf("operation was already cancelled on entry to cleanup boundary: %v", observed.ctx.Err())
	}

	fyne.DoAndWait(func() {
		a.cancelButton.OnTapped()
	})
	close(releaseCleanup)
	drainOperationFinalizer(t, a)

	if _, err := os.Stat(source); err != nil {
		t.Fatalf("source was removed after cancellation reached the cleanup boundary: %v", err)
	}
}

func TestRecursiveOperationKeepsWorkingAndProcessesEveryFile(t *testing.T) {
	t.Run("complete batch", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		dir := t.TempDir()
		files := []string{filepath.Join(dir, "first.txt"), filepath.Join(dir, "second.txt")}
		for _, path := range files {
			if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
		}

		type observation struct {
			path           string
			working        bool
			password       string
			keyfiles       []string
			keyfileOrdered bool
			comments       string
			paranoid       bool
			reedSolomon    bool
			deniability    bool
			split          bool
			chunkSize      int
			chunkUnit      fileops.SplitUnit
			delete         bool
		}
		observed := make(chan observation, len(files))
		a.operationExecutor = func(_ context.Context, input operationInput, _ volume.ProgressReporter) operationResult {
			observed <- observation{
				path:           input.inputFile,
				working:        a.State.IsWorking(),
				password:       string(input.password),
				keyfiles:       append([]string(nil), input.keyfiles...),
				keyfileOrdered: input.keyfileOrdered,
				comments:       input.comments,
				paranoid:       input.paranoid,
				reedSolomon:    input.reedSolomon,
				deniability:    input.deniability,
				split:          input.split,
				chunkSize:      input.chunkSize,
				chunkUnit:      input.chunkUnit,
				delete:         input.delete,
			}
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = files[0]
			a.State.OutputFile = files[0] + ".pcv"
			a.State.OnlyFiles = append([]string(nil), files...)
			a.State.AllFiles = append([]string(nil), files...)
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Keyfile = true
			a.State.Keyfiles = []string{"key-b", "key-a"}
			a.State.KeyfileOrdered = true
			a.State.Comments = "recursive comment"
			a.State.Paranoid = true
			a.State.ReedSolomon = true
			a.State.Deniability = true
			a.State.Split = true
			a.State.SplitSize = "64"
			a.State.SplitSelected = 2
			a.State.Delete = true
			a.State.Recursively = true
			a.startWork()
		})

		for i, want := range files {
			select {
			case got := <-observed:
				if got.path != want {
					t.Fatalf("executor input %d = %q; want %q", i, got.path, want)
				}
				if !got.working {
					t.Fatalf("Working was false when executor entered for item %d", i)
				}
				if got.password != "secret" || !reflect.DeepEqual(got.keyfiles, []string{"key-b", "key-a"}) || !got.keyfileOrdered {
					t.Fatalf("recursive credentials for item %d = password %q keyfiles %v ordered %v", i, got.password, got.keyfiles, got.keyfileOrdered)
				}
				if got.comments != "recursive comment" || !got.paranoid || !got.reedSolomon || !got.deniability || !got.delete {
					t.Fatalf("recursive options were not restored for item %d: %+v", i, got)
				}
				if !got.split || got.chunkSize != 64 || got.chunkUnit != fileops.SplitUnitGiB {
					t.Fatalf("recursive split options for item %d = split %v size %d unit %v", i, got.split, got.chunkSize, got.chunkUnit)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("executor did not receive recursive item %d", i)
			}
		}
		drainOperationFinalizer(t, a)
		if a.State.IsWorking() {
			t.Fatal("recursive finalizer did not perform the single final Working clear")
		}
		status := a.State.UISnapshot().Status
		if status.Kind != app.StatusRecursiveCompleted || status.Args.Count != len(files) {
			t.Fatalf("recursive status = %+v; want completed count %d", status, len(files))
		}
	})

	t.Run("shutdown before recursive selection commits", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		file := filepath.Join(t.TempDir(), "pending.txt")
		if err := os.WriteFile(file, []byte("payload"), 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = file
			a.State.OutputFile = file + ".pcv"
			a.State.OnlyFiles = []string{file}
			a.State.AllFiles = []string{file}
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Recursively = true
			a.startWork()
			a.workers.beginStop()
		})
		a.workers.wait()
		if got := calls.Load(); got != 0 {
			t.Fatalf("stale/unapplied recursive selection reached executor %d time(s); want zero", got)
		}
	})

	t.Run("selection failure is counted", func(t *testing.T) {
		fyneApp := newTestFyneApp(t)
		a := createUIReadyDropTestApp(t, fyneApp)
		file := filepath.Join(t.TempDir(), "disappears.txt")
		if err := os.WriteFile(file, []byte("payload"), 0o600); err != nil {
			t.Fatalf("write input: %v", err)
		}
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}

		fyne.DoAndWait(func() {
			a.State.Mode = "encrypt"
			a.State.InputFile = file
			a.State.OutputFile = file + ".pcv"
			a.State.OnlyFiles = []string{file}
			a.State.AllFiles = []string{file}
			a.State.Password = "secret"
			a.State.CPassword = "secret"
			a.State.Recursively = true
			a.startWork()
			if err := os.Remove(file); err != nil {
				t.Fatalf("remove captured input: %v", err)
			}
		})
		drainOperationFinalizer(t, a)
		if got := calls.Load(); got != 0 {
			t.Fatalf("failed recursive selection reached executor %d time(s); want zero", got)
		}
		status := a.State.UISnapshot().Status
		if status.Kind != app.StatusRecursiveFailedAll || status.Args.Count != 1 {
			t.Fatalf("selection failure status = %+v; want failed-all count 1", status)
		}
	})
}

// TestOnClickStartValidation tests the validation logic in onClickStart.
func TestOnClickStartValidation(t *testing.T) {
	newTestFyneApp(t)
	selected := filepath.Join(t.TempDir(), "selected.txt")
	if err := os.WriteFile(selected, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write selected input: %v", err)
	}

	assertRejected := func(t *testing.T, a *App) {
		t.Helper()
		var calls atomic.Int32
		a.operationExecutor = func(context.Context, operationInput, volume.ProgressReporter) operationResult {
			calls.Add(1)
			return operationResult{completed: true}
		}
		a.State.InputFile = selected
		a.State.OutputFile = selected + ".pcv"
		a.State.OnlyFiles = []string{selected}
		a.State.AllFiles = []string{selected}

		a.onClickStart()
		a.workers.wait()
		fyne.DoAndWait(func() {})
		if got := calls.Load(); got != 0 {
			t.Fatalf("invalid start reached operation executor %d time(s); want zero", got)
		}
		if a.State.IsWorking() {
			t.Fatal("invalid start entered working state")
		}
	}

	t.Run("NoMode", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = ""
		a.State.Password = "secret"
		assertRejected(t, a)
	})

	t.Run("NoCredentials", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = ""
		a.State.Keyfiles = nil
		assertRejected(t, a)
	})

	t.Run("EncryptPasswordMismatch", func(t *testing.T) {
		a := createTestApp(t)
		a.State.Mode = "encrypt"
		a.State.Password = "secret"
		a.State.CPassword = "different"
		assertRejected(t, a)
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

func TestCreateReporterCallbacksUpdateStateAndCancelButton(t *testing.T) {
	fyneApp := test.NewApp()
	t.Cleanup(fyneApp.Quit)

	a := createUIReadyDropTestApp(t, fyneApp)
	session := a.newOperationSession()
	a.setOperationSession(session)
	defer func() {
		session.cancel()
		a.clearOperationSession(session)
	}()
	fyne.DoAndWait(func() {
		a.showProgressModal(session)
	})

	reporter := a.CreateReporter(session)

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
	boundStatus, err := a.boundStatus.Get()
	if err != nil {
		t.Fatalf("read reporter status binding: %v", err)
	}
	if boundStatus != "Encrypting..." {
		t.Fatalf("status binding = %q; want %q", boundStatus, "Encrypting...")
	}
	boundProgress, err := a.boundProgress.Get()
	if err != nil {
		t.Fatalf("read reporter progress binding: %v", err)
	}
	if boundProgress != 0.5 {
		t.Fatalf("progress binding = %v; want 0.5", boundProgress)
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

// TestSplitUnitConversion verifies that splitUnitFromIndex turns each
// State.SplitSelected value into the fileops.SplitUnit the request adapter
// carries to the encryption operation.
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

// createTestApp creates a minimal App instance for testing.
func createTestApp(t *testing.T) *App {
	t.Helper()

	a, err := NewApp("v2.02")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}
	return a
}
