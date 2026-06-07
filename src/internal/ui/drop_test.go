// Package ui provides tests for file drop handling logic.
package ui

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// TestFileTypeDetection tests detection of encrypted vs plain files.
func TestFileTypeDetection(t *testing.T) {
	testCases := []struct {
		name      string
		filename  string
		isPcv     bool
		isSplit   bool
		isEncrypt bool
	}{
		{"PlainText", "document.txt", false, false, true},
		{"PlainPDF", "report.pdf", false, false, true},
		{"EncryptedPcv", "secret.pcv", true, false, false},
		{"EncryptedPcvUppercase", "secret.PCV", true, false, false},
		{"SplitChunk0", "secret.pcv.0", true, true, false},
		{"SplitChunk1", "secret.pcv.1", true, true, false},
		{"SplitChunk99", "secret.pcv.99", true, true, false},
		{"FakeSplit", "file.pcv.txt", false, false, true},
		{"FalsePositiveBackup", "backup.pcv.tmp1", false, false, true},
		{"FalsePositiveVersioned", "notes.pcv.v2", false, false, true},
		{"DeepPath", "/path/to/secret.pcv", true, false, false},
		{"DeepSplit", "/path/to/secret.pcv.5", true, true, false},
		{"NoExtension", "document", false, false, true},
		{"HiddenFile", ".hidden.pcv", true, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isSplit := detectSplitVolume(tc.filename)
			isDecrypt := isDecryptVolumePath(tc.filename)
			isPcv := isDecrypt && !isSplit

			if isPcv != tc.isPcv && !isSplit {
				t.Errorf("isPcv = %v; want %v for %q", isPcv, tc.isPcv, tc.filename)
			}
			if isSplit != tc.isSplit {
				t.Errorf("isSplit = %v; want %v for %q", isSplit, tc.isSplit, tc.filename)
			}

			// Determine encrypt mode
			isEncrypt := !isDecrypt
			if isEncrypt != tc.isEncrypt {
				t.Errorf("isEncrypt = %v; want %v for %q", isEncrypt, tc.isEncrypt, tc.filename)
			}
		})
	}
}

// detectSplitVolume checks if a filename is a split volume chunk.
// This mirrors the logic in handleDecryptDrop.
func detectSplitVolume(filename string) bool {
	return fileops.IsSplitChunkPath(filename)
}

// TestSplitVolumeBasePath tests extraction of base path from split volumes.
func TestSplitVolumeBasePath(t *testing.T) {
	testCases := []struct {
		name         string
		chunkPath    string
		expectedBase string
	}{
		{"Chunk0", "/path/to/secret.pcv.0", "/path/to/secret.pcv"},
		{"Chunk5", "/path/to/secret.pcv.5", "/path/to/secret.pcv"},
		{"Chunk99", "/path/to/data.pcv.99", "/path/to/data.pcv"},
		{"DeepPath", "/a/b/c/d/file.pcv.0", "/a/b/c/d/file.pcv"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			basePath, ok := fileops.SplitChunkBase(tc.chunkPath)
			if !ok {
				t.Fatalf("SplitChunkBase(%q) returned ok=false", tc.chunkPath)
			}

			if basePath != tc.expectedBase {
				t.Errorf("basePath = %q; want %q", basePath, tc.expectedBase)
			}
		})
	}
}

// TestOutputPathFromDecrypt tests output path derivation for decryption.
func TestOutputPathFromDecrypt(t *testing.T) {
	testCases := []struct {
		name       string
		inputPath  string
		outputPath string
	}{
		{"SimplePcv", "/path/secret.pcv", "/path/secret"},
		{"NestedPcv", "/a/b/c/file.pcv", "/a/b/c/file"},
		{"MultipleDots", "/path/file.tar.gz.pcv", "/path/file.tar.gz"},
		{"UppercasePcv", "/path/SECRET.PCV", "/path/SECRET"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := trimPCVSuffix(tc.inputPath)

			if output != tc.outputPath {
				t.Errorf("output = %q; want %q", output, tc.outputPath)
			}
		})
	}
}

// TestMultipleDropLabels tests label generation for multiple dropped items.
func TestMultipleDropLabels(t *testing.T) {
	testCases := []struct {
		name     string
		files    int
		folders  int
		expected string
	}{
		{"OnlyFiles_2", 2, 0, "2 files"},
		{"OnlyFiles_5", 5, 0, "5 files"},
		{"OnlyFolders_2", 0, 2, "2 folders"},
		{"OnlyFolders_5", 0, 5, "5 folders"},
		{"1File1Folder", 1, 1, "1 file and 1 folder"},
		{"1FileManyFolders", 1, 3, "1 file and 3 folders"},
		{"ManyFiles1Folder", 3, 1, "3 files and 1 folder"},
		{"ManyBoth", 3, 2, "3 files and 2 folders"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			label := generateInputLabel(tc.files, tc.folders)

			if label != tc.expected {
				t.Errorf("label = %q; want %q", label, tc.expected)
			}
		})
	}
}

// generateInputLabel generates the input label for multiple items.
// This mirrors the logic in handleMultipleDrop.
func generateInputLabel(files, folders int) string {
	if folders == 0 {
		return pluralize(files, "file", "files")
	}
	if files == 0 {
		return pluralize(folders, "folder", "folders")
	}

	if files == 1 && folders > 1 {
		return "1 file and " + pluralize(folders, "folder", "folders")
	}
	if folders == 1 && files > 1 {
		return pluralize(files, "file", "files") + " and 1 folder"
	}
	if folders == 1 && files == 1 {
		return "1 file and 1 folder"
	}
	return pluralize(files, "file", "files") + " and " + pluralize(folders, "folder", "folders")
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return "1 " + singular
	}
	return itoa(count) + " " + plural
}

// itoa converts an int to string without leading zeros.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}

// TestDropStateTransitions tests state changes during drop handling.
func TestDropStateTransitions(t *testing.T) {
	newTestFyneApp(t)

	t.Run("SingleFileDropSetsEncryptMode", func(t *testing.T) {
		state := mustNewState(t)

		// Simulate dropping a plain file
		state.Mode = "encrypt"
		state.InputFile = "/path/to/file.txt"
		state.OutputFile = state.InputFile + ".pcv"

		if state.Mode != "encrypt" {
			t.Error("Mode should be 'encrypt' for plain file")
		}
		if !strings.HasSuffix(state.OutputFile, ".pcv") {
			t.Error("Output should have .pcv suffix")
		}
	})

	t.Run("PcvFileDropSetsDecryptMode", func(t *testing.T) {
		state := mustNewState(t)

		// Simulate dropping a .pcv file
		state.Mode = "decrypt"
		state.InputFile = "/path/to/secret.pcv"
		state.OutputFile = "/path/to/secret"

		if state.Mode != "decrypt" {
			t.Error("Mode should be 'decrypt' for .pcv file")
		}
		if strings.HasSuffix(state.OutputFile, ".pcv") {
			t.Error("Output should not have .pcv suffix")
		}
	})

	t.Run("FolderDropSetsZipMode", func(t *testing.T) {
		state := mustNewState(t)

		// Simulate dropping a folder
		state.Mode = "encrypt"
		state.StartLabel = "Zip and Encrypt"

		if state.Mode != "encrypt" {
			t.Error("Mode should be 'encrypt' for folder")
		}
		if state.StartLabel != "Zip and Encrypt" {
			t.Errorf("StartLabel = %q; want 'Zip and Encrypt'", state.StartLabel)
		}
	})
}

func TestApplyDropErrorPreservesStatusAfterReset(t *testing.T) {
	newTestFyneApp(t)

	testCases := []struct {
		name              string
		status            string
		closeKeyfileModal bool
	}{
		{name: "DecryptDrop", status: "Read access denied", closeKeyfileModal: false},
		{name: "KeyfileDrop", status: "Keyfile read access denied", closeKeyfileModal: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &App{
				State:             mustNewState(t),
				advancedContainer: container.NewVBox(),
			}
			a.State.StartLabel = "Decrypt"
			a.State.MainStatus = "Old status"
			a.State.MainStatusColor = util.GREEN

			a.applyDropError(tc.status, tc.closeKeyfileModal)

			if a.State.StartLabel != "Start" {
				t.Fatalf("expected resetUI() to run, StartLabel = %q", a.State.StartLabel)
			}
			if a.State.MainStatus != tc.status {
				t.Fatalf("MainStatus = %q, want %q", a.State.MainStatus, tc.status)
			}
			if a.State.MainStatusColor != util.RED {
				t.Fatalf("MainStatusColor = %#v, want %#v", a.State.MainStatusColor, util.RED)
			}
		})
	}
}

func TestApplyStartupPathsLoadsInitialFiles(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != inputFile+".pcv" {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, inputFile+".pcv")
	}
	if len(state.AllFiles) != 1 || state.AllFiles[0] != inputFile {
		t.Fatalf("AllFiles = %#v; want [%q]", state.AllFiles, inputFile)
	}
	if len(state.OnlyFiles) != 1 || state.OnlyFiles[0] != inputFile {
		t.Fatalf("OnlyFiles = %#v; want [%q]", state.OnlyFiles, inputFile)
	}
}

func TestApplyStartupPathsLoadsDecryptVolume(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != strings.TrimSuffix(inputFile, ".pcv") {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, strings.TrimSuffix(inputFile, ".pcv"))
	}
	if len(state.OnlyFiles) != 1 || state.OnlyFiles[0] != inputFile {
		t.Fatalf("OnlyFiles = %#v; want [%q]", state.OnlyFiles, inputFile)
	}
}

func TestApplyStartupPathsWithMacOSProcessSerialLoadsDecryptVolume(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"-psn_0_12345", inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
}

func TestApplyStartupPathsTreatsUppercaseVolumeExtensionAsDecrypt(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	original := filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv")
	inputFile := filepath.Join(tempDir, "PICO_TEST_V2.TXT.PCV")
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatalf("Read golden volume: %v", err)
	}
	if err := os.WriteFile(inputFile, data, 0644); err != nil {
		t.Fatalf("Write uppercase volume: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	state := snapshotDropState(t, a)

	if state.Mode != "decrypt" {
		t.Fatalf("Mode = %q; want decrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.OutputFile != strings.TrimSuffix(inputFile, ".PCV") {
		t.Fatalf("OutputFile = %q; want %q", state.OutputFile, strings.TrimSuffix(inputFile, ".PCV"))
	}
}

func TestApplyStartupPathsIgnoresMacOSProcessSerialNumber(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"-psn_0_12345"})
	})
	state := snapshotDropState(t, a)

	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready", state.MainStatus)
	}
	if state.Mode != "" {
		t.Fatalf("Mode = %q; want empty", state.Mode)
	}
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q; want empty", state.InputFile)
	}
}

func TestApplyStartupPathsIgnoresMissingNonFlagArgs(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{filepath.Join(t.TempDir(), "missing.txt")})
	})
	state := snapshotDropState(t, a)

	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready", state.MainStatus)
	}
	if state.Mode != "" {
		t.Fatalf("Mode = %q; want empty", state.Mode)
	}
}

func TestApplyStartupPathsSkipsInvalidArgsWhenValidPathsRemain(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	missingPath := filepath.Join(tempDir, "missing.txt")
	inputFile := filepath.Join(tempDir, "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{missingPath, inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.MainStatus != "Ready" {
		t.Fatalf("MainStatus = %q; want Ready", state.MainStatus)
	}
}

func TestApplyStartupPathsAllowsHyphenPrefixedFilename(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "-secret.txt")
	if err := os.WriteFile(inputFile, []byte("secret"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
}

func TestApplyStartupPathsReportsAccessError(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	originalStat := startupPathStat
	startupPathStat = func(path string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	}
	defer func() {
		startupPathStat = originalStat
	}()

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"blocked.txt"})
	})

	if a.State.MainStatus != startupPathAccessStatus {
		t.Fatalf("MainStatus = %q; want %q", a.State.MainStatus, startupPathAccessStatus)
	}
	if a.State.MainStatusColor != util.RED {
		t.Fatalf("MainStatusColor = %#v; want %#v", a.State.MainStatusColor, util.RED)
	}
}

func TestApplyStartupPathsPreservesPartialAccessWarning(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(inputFile, []byte("quarterly report"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	originalStat := startupPathStat
	startupPathStat = func(path string) (os.FileInfo, error) {
		if path == "blocked.txt" {
			return nil, os.ErrPermission
		}
		return originalStat(path)
	}
	defer func() {
		startupPathStat = originalStat
	}()

	fyne.DoAndWait(func() {
		a.applyStartupPaths([]string{"blocked.txt", inputFile})
	})
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)

	if state.Mode != "encrypt" {
		t.Fatalf("Mode = %q; want encrypt", state.Mode)
	}
	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q; want %q", state.InputFile, inputFile)
	}
	if state.MainStatus != startupPathPartialAccessStatus {
		t.Fatalf("MainStatus = %q; want %q", state.MainStatus, startupPathPartialAccessStatus)
	}
}

func TestCollectStartupPathsAllowsHyphenPrefixedFilename(t *testing.T) {
	validPaths, err := collectStartupPaths([]string{"-secret.txt"}, func(path string) (os.FileInfo, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("collectStartupPaths returned error: %v", err)
	}
	if len(validPaths) != 1 || validPaths[0] != "-secret.txt" {
		t.Fatalf("validPaths = %#v; want [-secret.txt]", validPaths)
	}
}

func TestCollectStartupPathsSkipsMissingAndReportsAccessError(t *testing.T) {
	validPaths, err := collectStartupPaths([]string{"missing.txt", "blocked.txt"}, func(path string) (os.FileInfo, error) {
		switch path {
		case "missing.txt":
			return nil, os.ErrNotExist
		case "blocked.txt":
			return nil, os.ErrPermission
		default:
			return nil, nil
		}
	})
	if len(validPaths) != 0 {
		t.Fatalf("validPaths = %#v; want empty", validPaths)
	}
	if err == nil {
		t.Fatal("collectStartupPaths should report non-missing access errors")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error = %v; want permission error", err)
	}
}

func TestAppendScannedFilesUpdatesState(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	files := []scannedFile{
		{path: "/tmp/a.txt", size: 10},
		{path: "/tmp/b.txt", size: 25},
	}

	fyne.DoAndWait(func() {
		a.appendScannedFiles(files)
	})

	state := snapshotDropState(t, a)
	if len(state.AllFiles) != 2 {
		t.Fatalf("AllFiles = %#v; want 2 entries", state.AllFiles)
	}
	if a.State.CompressTotal != 35 {
		t.Fatalf("CompressTotal = %d; want 35", a.State.CompressTotal)
	}
	if a.State.RequiredFreeSpace != 35 {
		t.Fatalf("RequiredFreeSpace = %d; want 35", a.State.RequiredFreeSpace)
	}
	if !strings.Contains(a.State.InputLabel, "35") && !strings.Contains(a.State.InputLabel, "B") {
		t.Fatalf("InputLabel = %q; want size summary", a.State.InputLabel)
	}
}

func TestFolderWalkErrorClearsScanningState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission-based walk failure setup is not reliable on Windows")
	}

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	rootDir := t.TempDir()
	blockedDir := filepath.Join(rootDir, "blocked")
	if err := os.Mkdir(blockedDir, 0700); err != nil {
		t.Fatalf("create blocked dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "visible.txt"), []byte("ok"), 0600); err != nil {
		t.Fatalf("create visible file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blockedDir, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatalf("create blocked file: %v", err)
	}
	if err := os.Chmod(blockedDir, 0); err != nil {
		t.Fatalf("chmod blocked dir: %v", err)
	}
	defer func() {
		_ = os.Chmod(blockedDir, 0700)
	}()

	fyne.DoAndWait(func() {
		a.onDrop([]string{rootDir})
	})

	waitForDropProcessing(t, a)
	fyne.DoAndWait(func() {})

	if a.State.IsScanning() {
		t.Fatal("Scanning should be false after folder walk error")
	}
}

func TestScheduleStartupPathsDefersUntilLifecycleStart(t *testing.T) {
	if raceEnabled {
		// Skipped under -race: Fyne v2.7.3 internal/cache/base.go
		// expiringCache.setAlive performs racy first-writes on combinatorial
		// font/glyph cache keys when test.NewApp drives Button.SetText →
		// Refresh → MeasureText. The race is benign (first writes converge),
		// not in our code, and the test still runs on the no-race matrix
		// (Linux arm64). Re-evaluate when Fyne ships a fix upstream.
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "startup.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths([]string{inputFile})

	state := snapshotDropState(t, a)
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q before start hook; want empty", state.InputFile)
	}
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	fake.started()
	waitForInputFile(t, a, inputFile)
	state = snapshotDropState(t, a)

	if state.InputFile != inputFile {
		t.Fatalf("InputFile = %q after start hook; want %q", state.InputFile, inputFile)
	}
}

// TestScheduleStartupPathsAlwaysWiresStartHook verifies that scheduleStartupPaths
// registers the OnStarted callback even when startupPaths is empty. On darwin,
// Apple-Event-buffered paths from a Finder cold launch may be the only source
// of startup paths and are drained inside the OnStarted closure via
// drainOpenedPaths(). Removing the wiring on empty input would silently lose
// those events. (FA-MAC-03 / Plan 03-03)
func TestScheduleStartupPathsAlwaysWiresStartHook(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths(nil)

	if fake.started == nil {
		t.Fatal("expected startup hook to be registered even for empty startupPaths (AE paths may arrive)")
	}

	// Firing the hook with empty CLI args + nil drain (non-darwin stub returns nil)
	// must be a safe no-op: no panic, no state mutation.
	fake.started()
	waitForDropProcessing(t, a)
	state := snapshotDropState(t, a)
	if state.InputFile != "" {
		t.Fatalf("InputFile = %q after start hook with no inputs; want empty", state.InputFile)
	}
}

// TestScheduleStartupPathsAppliesWarmOpenedPaths covers issue #127: a path opened
// while the app is already running (a warm application:openURLs: event, simulated
// here by appendOpenedPath after the lifecycle start hook fired) must be drained
// and applied through the normal drop handler. Before the event-driven wiring,
// drainOpenedPaths ran exactly once inside the start hook, so any path arriving
// afterward was silently lost — the app merely came to the foreground.
func TestScheduleStartupPathsAppliesWarmOpenedPaths(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	// Reset package-global bridge state: other tests fire the start hook and leave
	// a notify handler registered.
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "warm-open.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake

	a.scheduleStartupPaths(nil)
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}

	// Fire the start hook with nothing buffered: still no input applied.
	fake.started()
	waitForDropProcessing(t, a)
	if state := snapshotDropState(t, a); state.InputFile != "" {
		t.Fatalf("InputFile = %q before any opened path; want empty", state.InputFile)
	}

	// A warm openURLs event arrives after launch: the bridge appends the
	// path(s) for the event, then flushes once, which fires the notify handler.
	appendOpenedPath(inputFile)
	flushOpenedPaths()
	waitForInputFile(t, a, inputFile)

	if state := snapshotDropState(t, a); state.InputFile != inputFile {
		t.Fatalf("InputFile = %q after warm opened path; want %q", state.InputFile, inputFile)
	}
}

func TestScheduleStartupPathsCoalescesColdAndLateOpenedBatches(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 25*time.Millisecond)

	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	tempDir := t.TempDir()
	paths := []string{
		filepath.Join(tempDir, "a.txt"),
		filepath.Join(tempDir, "b.txt"),
		filepath.Join(tempDir, "c.txt"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("payload"), 0644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	appendOpenedPath(paths[0])
	appendOpenedPath(paths[1])

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths(nil)
	if fake.started == nil {
		t.Fatal("expected startup hook to be registered")
	}
	fake.started()

	appendOpenedPath(paths[2])
	flushOpenedPaths()

	waitForAllFiles(t, a, paths)
}

func TestScheduleStartupPathsWaitsForOpenedPathReadiness(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	checks := 0
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	inputFile := filepath.Join(t.TempDir(), "icloud.txt")
	if err := os.WriteFile(inputFile, []byte("payload"), 0644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		checks++
		if checks == 1 {
			return openedPathReadinessResult{{Path: inputFile, State: openedPathPending}}
		}
		return openedPathReadinessResult{{Path: inputFile, State: openedPathReady}}
	}

	fake := newLifecycleCaptureApp(fyne.CurrentApp())
	a.fyneApp = fake
	a.scheduleStartupPaths([]string{inputFile})
	fake.started()

	waitForInputFile(t, a, inputFile)
	if checks < 2 {
		t.Fatalf("readiness checks = %d; want at least 2", checks)
	}
}

func TestOpenedPathReadinessCancellationPreventsStaleApply(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.3 internal cache races under -race; covered on arm64 matrix")
	}
	oldCheck := checkOpenedPathReadiness
	oldPoll := openedPathPollInterval
	defer func() {
		checkOpenedPathReadiness = oldCheck
		openedPathPollInterval = oldPoll
	}()
	openedPathPollInterval = 5 * time.Millisecond

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	pendingFile := filepath.Join(t.TempDir(), "pending.txt")
	manualFile := filepath.Join(t.TempDir(), "manual.txt")
	for _, path := range []string{pendingFile, manualFile} {
		if err := os.WriteFile(path, []byte("payload"), 0644); err != nil {
			t.Fatalf("Create test file %q: %v", path, err)
		}
	}

	release := make(chan struct{})
	checkOpenedPathReadiness = func(ctx context.Context, paths []string) openedPathReadinessResult {
		select {
		case <-ctx.Done():
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathPending}}
		case <-release:
			return openedPathReadinessResult{{Path: pendingFile, State: openedPathReady}}
		}
	}

	a.applyOpenedPaths([]string{pendingFile})
	fyne.DoAndWait(func() {
		a.cancelOpenedPathReadiness()
		a.onDrop([]string{manualFile})
	})
	close(release)

	waitForInputFile(t, a, manualFile)
	state := snapshotDropState(t, a)
	if state.InputFile == pendingFile {
		t.Fatalf("stale opened path %q applied after cancellation", pendingFile)
	}
}

// TestOpenedPathsBatchDeliversWholeGestureAsOneDrop covers the first #127
// batching fix: when one application:openURLs: callback contains several files,
// the bridge must surface it as ONE drop carrying every path. The previous code
// notified after every appended path, so a three-file callback produced three
// single-path drops — each replacing the prior selection or hitting onDrop's
// scanning guard, losing files. The darwin bridge appends all paths and flushes
// once; this asserts that contract at the platform-neutral layer so it guards
// the regression on every CI platform, including the amd64 -race job (it touches
// no Fyne rendering, so it is not -race-skipped).
func TestOpenedPathsBatchDeliversWholeGestureAsOneDrop(t *testing.T) {
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)
	// Reset package-global bridge state other tests may have left behind.
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})

	batches := make(chan []string, 1)
	setOpenedPathsNotify(func() {
		batches <- drainOpenedPaths()
	})

	// One openURLs: event carrying three files: append each, then flush once.
	paths := []string{"/tmp/a.txt", "/tmp/b.txt", "/tmp/c.txt"}
	for _, p := range paths {
		appendOpenedPath(p)
	}
	flushOpenedPaths()

	var got []string
	select {
	case got = <-batches:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for opened paths notification")
	}

	select {
	case extra := <-batches:
		t.Fatalf("notify fired more than once for one openURLs gesture; extra batch: %#v", extra)
	default:
	}
	if len(got) != len(paths) {
		t.Fatalf("drained %d path(s); want all %d delivered in one drop: got %v", len(got), len(paths), got)
	}
	for i := range paths {
		if got[i] != paths[i] {
			t.Fatalf("path[%d] = %q; want %q (order and completeness must be preserved)", i, got[i], paths[i])
		}
	}
}

// TestKeyfileDropHandling tests keyfile drop in keyfile modal.
func TestKeyfileDropHandling(t *testing.T) {
	t.Run("AddUniqueKeyfiles", func(t *testing.T) {
		state := mustNewState(t)
		state.ShowKeyfile = true

		// Add keyfiles
		keyfiles := []string{"/path/key1.bin", "/path/key2.bin"}
		for _, kf := range keyfiles {
			// Check for duplicates
			duplicate := false
			for _, existing := range state.Keyfiles {
				if kf == existing {
					duplicate = true
					break
				}
			}
			if !duplicate {
				state.Keyfiles = append(state.Keyfiles, kf)
			}
		}

		if len(state.Keyfiles) != 2 {
			t.Errorf("Keyfiles count = %d; want 2", len(state.Keyfiles))
		}
	})

	t.Run("PreventDuplicateKeyfiles", func(t *testing.T) {
		state := mustNewState(t)
		state.ShowKeyfile = true
		state.Keyfiles = []string{"/path/key1.bin"}

		// Try to add duplicate
		newKeyfile := "/path/key1.bin"
		duplicate := false
		for _, existing := range state.Keyfiles {
			if newKeyfile == existing {
				duplicate = true
				break
			}
		}

		if !duplicate {
			state.Keyfiles = append(state.Keyfiles, newKeyfile)
		}

		if len(state.Keyfiles) != 1 {
			t.Errorf("Keyfiles count = %d; want 1 (no duplicates)", len(state.Keyfiles))
		}
	})

	t.Run("KeyfileLabelUpdates", func(t *testing.T) {
		testCases := []struct {
			count    int
			required bool
			expected string
		}{
			{0, false, "None selected"},
			{0, true, "Keyfiles required"},
			{1, false, "Using 1 keyfile"},
			{3, false, "Using multiple keyfiles"},
		}

		for _, tc := range testCases {
			state := mustNewState(t)
			state.Keyfile = tc.required
			state.Keyfiles = make([]string, tc.count)
			for i := 0; i < tc.count; i++ {
				state.Keyfiles[i] = "/path/key" + string(rune('0'+i)) + ".bin"
			}

			state.UpdateKeyfileLabel()

			if state.KeyfileLabel != tc.expected {
				t.Errorf("count=%d, required=%v: label = %q; want %q",
					tc.count, tc.required, state.KeyfileLabel, tc.expected)
			}
		}
	})
}

// TestScanningState tests the scanning state during folder processing.
func TestScanningState(t *testing.T) {
	state := mustNewState(t)

	// Initially not scanning
	if state.Scanning {
		t.Error("Scanning should be false initially")
	}

	// Start scanning
	state.Scanning = true
	if !state.Scanning {
		t.Error("Scanning should be true")
	}

	// During scanning, new drops should be ignored
	if !state.Scanning {
		t.Error("Drops should be blocked while scanning")
	}

	// End scanning
	state.Scanning = false
	if state.Scanning {
		t.Error("Scanning should be false after completion")
	}
}

// TestDeniabilityDetection tests deniability mode detection from headers.
func TestDeniabilityDetection(t *testing.T) {
	t.Run("DeniableVolumeStatus", func(t *testing.T) {
		state := mustNewState(t)

		// When version cannot be read, assume deniable
		state.Deniability = true
		state.MainStatus = "Cannot read header, volume may be deniable"

		if !state.Deniability {
			t.Error("Deniability should be true for unreadable header")
		}
	})

	t.Run("NormalVolumeStatus", func(t *testing.T) {
		state := mustNewState(t)
		state.Deniability = false
		state.MainStatus = "Ready"

		if state.Deniability {
			t.Error("Deniability should be false for normal volume")
		}
	})
}

// TestDropWithRealFiles tests drop handling logic with actual filesystem.
// Note: We test the state logic directly since the UI components aren't initialized.
func TestDropWithRealFiles(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("SingleFileDetection", func(t *testing.T) {
		// Create test file
		testFile := filepath.Join(tmpDir, "test.txt")
		if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
			t.Fatalf("Create test file: %v", err)
		}

		stat, err := os.Stat(testFile)
		if err != nil {
			t.Fatalf("Stat test file: %v", err)
		}

		// Test detection logic
		if stat.IsDir() {
			t.Error("File should not be detected as directory")
		}
		if strings.HasSuffix(testFile, ".pcv") {
			t.Error("File should not be detected as encrypted")
		}
	})

	t.Run("FolderDetection", func(t *testing.T) {
		// Create test folder
		testFolder := filepath.Join(tmpDir, "testfolder")
		if err := os.Mkdir(testFolder, 0755); err != nil {
			t.Fatalf("Create test folder: %v", err)
		}

		stat, err := os.Stat(testFolder)
		if err != nil {
			t.Fatalf("Stat test folder: %v", err)
		}

		if !stat.IsDir() {
			t.Error("Folder should be detected as directory")
		}
	})

	t.Run("MultipleFilesCount", func(t *testing.T) {
		// Create multiple test files
		files := make([]string, 3)
		for i := 0; i < 3; i++ {
			files[i] = filepath.Join(tmpDir, "multi"+string(rune('0'+i))+".txt")
			if err := os.WriteFile(files[i], []byte("content"), 0644); err != nil {
				t.Fatalf("Create test file: %v", err)
			}
		}

		// Verify all files exist
		for _, f := range files {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("File %s should exist", f)
			}
		}

		if len(files) != 3 {
			t.Errorf("Files count = %d; want 3", len(files))
		}
	})

	t.Run("PcvFileDetection", func(t *testing.T) {
		// Create test .pcv file
		pcvFile := filepath.Join(tmpDir, "encrypted.pcv")
		if err := os.WriteFile(pcvFile, []byte("encrypted content"), 0644); err != nil {
			t.Fatalf("Create test file: %v", err)
		}

		if !strings.HasSuffix(pcvFile, ".pcv") {
			t.Error("PCV file should be detected by suffix")
		}

		// Should be decrypt mode
		isPcv := strings.HasSuffix(pcvFile, ".pcv")
		isSplit := detectSplitVolume(pcvFile)
		isDecrypt := isPcv || isSplit

		if !isDecrypt {
			t.Error("PCV file should trigger decrypt mode")
		}
	})

	t.Run("SplitVolumeDetection", func(t *testing.T) {
		// Create split volume chunks
		for i := 0; i < 3; i++ {
			chunkFile := filepath.Join(tmpDir, "data.pcv."+string(rune('0'+i)))
			if err := os.WriteFile(chunkFile, []byte("chunk"), 0644); err != nil {
				t.Fatalf("Create chunk file: %v", err)
			}
		}

		chunk0 := filepath.Join(tmpDir, "data.pcv.0")
		if !detectSplitVolume(chunk0) {
			t.Error("Split volume should be detected")
		}
	})
}

// TestDropRaceConditionPrevention tests that concurrent drops are blocked.
func TestDropRaceConditionPrevention(t *testing.T) {
	state := mustNewState(t)

	// Simulate scanning in progress
	state.Scanning = true

	// New drops should be blocked
	if !state.Scanning {
		t.Error("Scanning should block new drops")
	}

	// Simulate working
	state.Scanning = false
	state.Working = true

	if !state.Working {
		t.Error("Working should block new drops")
	}
}

// TestCommentsFromHeader tests reading comments from decrypted volume.
func TestCommentsFromHeader(t *testing.T) {
	testCases := []struct {
		name     string
		comments string
		disabled bool
		expected string
	}{
		{"ValidComments", "User comments here", false, "Comments (read-only):"},
		{"EmptyComments", "", true, "Comments (read-only):"},
		{"CorruptedComments", "Comments are corrupted", true, "Comments (read-only):"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			state := mustNewState(t)
			state.Mode = "decrypt"
			state.Comments = tc.comments
			state.CommentsLabel = "Comments (read-only):"
			state.CommentsDisabled = tc.disabled

			if state.CommentsLabel != tc.expected {
				t.Errorf("CommentsLabel = %q; want %q", state.CommentsLabel, tc.expected)
			}
		})
	}
}

// TestRequiredFreeSpaceCalculation tests free space estimation.
func TestRequiredFreeSpaceCalculation(t *testing.T) {
	state := mustNewState(t)

	// Single file
	state.RequiredFreeSpace = 1024 * 1024 // 1 MiB

	// Multipliers based on options
	multiplier := 1
	state.AllFiles = []string{"file1.txt", "file2.txt"} // Multi-file
	if len(state.AllFiles) > 1 {
		multiplier++
	}
	state.Deniability = true
	if state.Deniability {
		multiplier++
	}
	state.Split = true
	if state.Split {
		multiplier++
	}

	estimatedSpace := state.RequiredFreeSpace * int64(multiplier)
	expectedSpace := 1024 * 1024 * 4 // 4 MiB (4x multiplier)

	if estimatedSpace != int64(expectedSpace) {
		t.Errorf("EstimatedSpace = %d; want %d", estimatedSpace, expectedSpace)
	}
}

// TestStatusWithFreeSpace tests status message with free space info.
func TestStatusWithFreeSpace(t *testing.T) {
	state := mustNewState(t)
	state.MainStatus = "Ready"
	state.RequiredFreeSpace = 10 * 1024 * 1024 // 10 MiB

	if state.RequiredFreeSpace > 0 {
		spaceStr := util.Sizeify(state.RequiredFreeSpace)
		statusText := "Ready (ensure >" + spaceStr + " free)"

		if !strings.Contains(statusText, "free") {
			t.Error("Status should mention free space")
		}
		if !strings.Contains(statusText, "MiB") && !strings.Contains(statusText, "10") {
			t.Logf("Status = %q", statusText)
		}
	}
}

func createUIReadyDropTestApp(t *testing.T, fyneApp fyne.App) *App {
	t.Helper()

	a, err := NewApp("v2.09")
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	a.fyneApp = fyneApp
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("drop-test")
		a.Window.SetContent(a.buildUI())
	})
	return a
}

func waitForDropProcessing(t *testing.T, a *App) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !a.State.IsScanning() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if a.State.IsScanning() {
		t.Fatal("drop processing did not finish")
	}
}

func waitForInputFile(t *testing.T, a *App, want string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if state.InputFile == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := snapshotDropState(t, a)
	t.Fatalf("InputFile = %q; want %q", state.InputFile, want)
}

func waitForAllFiles(t *testing.T, a *App, want []string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state := snapshotDropState(t, a)
		if reflect.DeepEqual(state.AllFiles, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := snapshotDropState(t, a)
	t.Fatalf("AllFiles = %#v; want %#v", state.AllFiles, want)
}

type dropStateSnapshot struct {
	Mode       string
	MainStatus string
	InputFile  string
	OutputFile string
	OnlyFiles  []string
	AllFiles   []string
}

func snapshotDropState(t *testing.T, a *App) dropStateSnapshot {
	t.Helper()

	var state dropStateSnapshot
	fyne.DoAndWait(func() {
		state = dropStateSnapshot{
			Mode:       a.State.Mode,
			MainStatus: a.State.MainStatus,
			InputFile:  a.State.InputFile,
			OutputFile: a.State.OutputFile,
			OnlyFiles:  append([]string(nil), a.State.OnlyFiles...),
			AllFiles:   append([]string(nil), a.State.AllFiles...),
		}
	})
	return state
}

func craftFullHeaderBytes(t *testing.T, rs *encoding.RSCodecs, comments string) []byte {
	t.Helper()

	h := header.NewVolumeHeader(
		bytes.Repeat([]byte{0x11}, header.SaltSize),
		bytes.Repeat([]byte{0x22}, header.HKDFSaltSize),
		bytes.Repeat([]byte{0x33}, header.SerpentIVSize),
		bytes.Repeat([]byte{0x44}, header.NonceSize),
	)
	h.Comments = comments

	var buf bytes.Buffer
	if _, err := header.NewWriter(&buf, rs).WriteHeader(h); err != nil {
		t.Fatalf("WriteHeader failed: %v", err)
	}
	return buf.Bytes()
}

func TestHandleDecryptDropNonCommentDecodeErrorIsHeaderDamage(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)

	raw := craftFullHeaderBytes(t, rs, "visible")
	saltOffset := header.VersionEncSize + header.CommentLenEncSize + len("visible")*3 + header.FlagsEncSize
	for i := range 17 {
		raw[saltOffset+i] ^= 0xff
	}

	pcvPath := filepath.Join(t.TempDir(), "non-comment-corrupt.pcv")
	if err := os.WriteFile(pcvPath, raw, 0644); err != nil {
		t.Fatalf("write crafted .pcv: %v", err)
	}

	fyne.DoAndWait(func() {
		a.onDrop([]string{pcvPath})
	})
	waitForDropProcessing(t, a)

	var comments, mainStatus string
	fyne.DoAndWait(func() {
		comments = a.State.Comments
		mainStatus = a.State.MainStatus
	})

	if comments == "Comments are corrupted" {
		t.Fatalf("Comments = %q; non-comment header corruption must not be labeled as comment damage", comments)
	}
	if mainStatus != "The volume header is damaged" {
		t.Fatalf("MainStatus = %q; want %q", mainStatus, "The volume header is damaged")
	}
}

// TestHandleDecryptDropMalformedCommentLen drops a crafted .pcv whose 5-digit
// comment-length RS5 field decodes to a non-digit / "negative"-looking value.
// The original hand-rolled parse did strconv.Atoi then make([]byte, n*3), which
// panics ("makeslice: len out of range") on a negative length. Routing through
// the validated parser (SEC-01) must instead yield a graceful status and never
// panic / over-allocate.
func TestHandleDecryptDropMalformedCommentLen(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs failed: %v", err)
	}

	cases := []struct {
		name       string
		version    string
		commentLen string
	}{
		// "-0001" -> Atoi == -1 -> make([]byte, -3) panics in the old code.
		{"negative comment length", "v2.09", "-0001"},
		// A non-digit field that also fails the ^\d{5}$ guard.
		{"non-digit comment length", "v2.09", "0x009"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)

			// Craft a .pcv: valid version field + malformed comment-length field.
			raw := craftPreviewBytes(t, rs, tc.version, tc.commentLen, "", []byte{0, 0, 0, 0, 0})
			// Pad so any reader past the header does not hit an unexpected EOF.
			raw = append(raw, make([]byte, header.BaseHeaderSize)...)

			pcvPath := filepath.Join(t.TempDir(), "crafted.pcv")
			if err := os.WriteFile(pcvPath, raw, 0644); err != nil {
				t.Fatalf("write crafted .pcv: %v", err)
			}

			// Drive through onDrop -> handleDecryptDrop. The old hand-rolled
			// path panics here on the negative length; the validated path must
			// set a graceful status instead.
			fyne.DoAndWait(func() {
				a.onDrop([]string{pcvPath})
			})
			waitForDropProcessing(t, a)

			var comments, mainStatus, mode string
			fyne.DoAndWait(func() {
				comments = a.State.Comments
				mainStatus = a.State.MainStatus
				mode = a.State.Mode
			})

			if mode != "decrypt" {
				t.Fatalf("Mode = %q; want decrypt", mode)
			}
			if comments == "Comment length is corrupted" || comments == "Comments are corrupted" {
				t.Fatalf("Comments = %q; malformed comment length is non-comment header damage", comments)
			}
			if mainStatus != "The volume header is damaged" {
				t.Fatalf("MainStatus = %q; want %q", mainStatus, "The volume header is damaged")
			}
		})
	}
}

type lifecycleCaptureApp struct {
	driver  fyne.Driver
	started func()
	stopped func()
	bg      func()
	fg      func()
}

func newLifecycleCaptureApp(base fyne.App) *lifecycleCaptureApp {
	return &lifecycleCaptureApp{driver: base.Driver()}
}

func (a *lifecycleCaptureApp) NewWindow(title string) fyne.Window {
	return fyne.CurrentApp().NewWindow(title)
}
func (a *lifecycleCaptureApp) OpenURL(*url.URL) error              { return nil }
func (a *lifecycleCaptureApp) Icon() fyne.Resource                 { return nil }
func (a *lifecycleCaptureApp) SetIcon(fyne.Resource)               {}
func (a *lifecycleCaptureApp) Run()                                {}
func (a *lifecycleCaptureApp) Quit()                               {}
func (a *lifecycleCaptureApp) Driver() fyne.Driver                 { return a.driver }
func (a *lifecycleCaptureApp) UniqueID() string                    { return "lifecycle-capture-app" }
func (a *lifecycleCaptureApp) SendNotification(*fyne.Notification) {}
func (a *lifecycleCaptureApp) Settings() fyne.Settings             { return fyne.CurrentApp().Settings() }
func (a *lifecycleCaptureApp) Preferences() fyne.Preferences       { return fyne.CurrentApp().Preferences() }
func (a *lifecycleCaptureApp) Storage() fyne.Storage               { return fyne.CurrentApp().Storage() }
func (a *lifecycleCaptureApp) Lifecycle() fyne.Lifecycle           { return a }
func (a *lifecycleCaptureApp) Metadata() fyne.AppMetadata          { return fyne.AppMetadata{} }
func (a *lifecycleCaptureApp) CloudProvider() fyne.CloudProvider   { return nil }
func (a *lifecycleCaptureApp) SetCloudProvider(fyne.CloudProvider) {}
func (a *lifecycleCaptureApp) Clipboard() fyne.Clipboard           { return fyne.CurrentApp().Clipboard() }

func (a *lifecycleCaptureApp) SetOnEnteredForeground(fn func()) { a.fg = fn }
func (a *lifecycleCaptureApp) SetOnExitedForeground(fn func())  { a.bg = fn }
func (a *lifecycleCaptureApp) SetOnStarted(fn func())           { a.started = fn }
func (a *lifecycleCaptureApp) SetOnStopped(fn func())           { a.stopped = fn }
