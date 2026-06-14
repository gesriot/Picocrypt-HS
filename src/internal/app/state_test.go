package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
)

// repoRoot walks up from the test working directory to the repository root —
// the first ancestor that contains both the VERSION file and .github/workflows.
// Mirrors the established pattern in internal/distmeta and internal/workflowpolicy
// (no repoRoot exists in package app). Used by TestStateVersion to tie the
// app.Version const to the canonical VERSION file.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for {
		_, verErr := os.Stat(filepath.Join(current, "VERSION"))
		_, wfErr := os.Stat(filepath.Join(current, ".github", "workflows"))
		if verErr == nil && wfErr == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("could not find repository root (dir with VERSION and .github/workflows) from test working directory")
		}
		current = parent
	}
}

// mustNewState builds a *State for tests, failing the test if RS-codec
// initialization returns an error. Centralizes the (*State, error) call so the
// many table tests below stay readable after APP-01 changed NewState's signature.
func mustNewState(t *testing.T) *State {
	t.Helper()
	s, err := NewState()
	if err != nil {
		t.Fatalf("NewState() returned error: %v", err)
	}
	return s
}

// TestNewStateRSInitFailure proves APP-01/D-05: when the RS-codec constructor
// fails, NewState returns a non-nil error (wrapping the cause) and a nil *State,
// and never panics. The newRSCodecs package-level seam is overridden to force
// the failure, mirroring the Phase 3/4 var-seam override+restore pattern.
func TestNewStateRSInitFailure(t *testing.T) {
	orig := newRSCodecs
	t.Cleanup(func() { newRSCodecs = orig })

	forced := errors.New("forced RS init failure")
	newRSCodecs = func() (*encoding.RSCodecs, error) {
		return nil, forced
	}

	// Must not panic; recover only to surface a clearer failure if it does.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewState() panicked instead of returning an error: %v", r)
		}
	}()

	state, err := NewState()
	if err == nil {
		t.Fatal("NewState() error = nil; want non-nil on RS-init failure")
	}
	if state != nil {
		t.Errorf("NewState() state = %v; want nil on error", state)
	}
	if !errors.Is(err, forced) {
		t.Errorf("NewState() error = %v; want wrapping %v", err, forced)
	}
	if !strings.Contains(err.Error(), "init RS codecs") {
		t.Errorf("NewState() error = %q; want it to mention 'init RS codecs'", err.Error())
	}
}

func TestNewState(t *testing.T) {
	state := mustNewState(t)

	// Check defaults
	if state.InputLabel != "Drop files and folders into this window" {
		t.Errorf("InputLabel = %q; want default", state.InputLabel)
	}
	if state.KeyfileLabel != "None selected" {
		t.Errorf("KeyfileLabel = %q; want 'None selected'", state.KeyfileLabel)
	}
	if state.CommentsLabel != "Comments:" {
		t.Errorf("CommentsLabel = %q; want 'Comments:'", state.CommentsLabel)
	}
	if state.StartLabel != "Start" {
		t.Errorf("StartLabel = %q; want 'Start'", state.StartLabel)
	}
	if state.MainStatus != "Ready" {
		t.Errorf("MainStatus = %q; want 'Ready'", state.MainStatus)
	}
	if state.MainStatusColor != util.WHITE {
		t.Error("MainStatusColor should be WHITE")
	}
	if state.PasswordMode != PasswordModeHidden {
		t.Error("PasswordMode should be Hidden")
	}
	if state.PasswordStateLabel != "Show" {
		t.Errorf("PasswordStateLabel = %q; want 'Show'", state.PasswordStateLabel)
	}
	if state.PassgenLength != 32 {
		t.Errorf("PassgenLength = %d; want 32", state.PassgenLength)
	}
	if state.SplitSelected != 1 {
		t.Errorf("SplitSelected = %d; want 1 (MiB)", state.SplitSelected)
	}
	if !state.FastDecode {
		t.Error("FastDecode should be true by default")
	}
	if state.DPI != 1.0 {
		t.Errorf("DPI = %f; want 1.0", state.DPI)
	}

	// Check RS codecs are initialized
	if state.RSCodecs == nil {
		t.Error("RSCodecs should be initialized")
	}
	if state.RS1 == nil || state.RS128 == nil {
		t.Error("RS codecs should be initialized")
	}
}

func TestStateReset(t *testing.T) {
	state := mustNewState(t)

	// Modify state
	state.Mode = "encrypt"
	state.Working = true
	state.Password = "secret"
	state.Keyfiles = []string{"key1", "key2"}
	state.Paranoid = true
	state.ShowProgress = true

	// Reset
	state.Reset()

	// Check all fields are reset
	if state.Mode != "" {
		t.Errorf("Mode = %q; want empty", state.Mode)
	}
	if state.Working {
		t.Error("Working should be false")
	}
	if state.Password != "" {
		t.Error("Password should be empty")
	}
	if len(state.Keyfiles) != 0 {
		t.Error("Keyfiles should be empty")
	}
	if state.Paranoid {
		t.Error("Paranoid should be false")
	}
	if state.ShowProgress {
		t.Error("ShowProgress should be false")
	}

	// Check defaults are restored
	if state.MainStatus != "Ready" {
		t.Errorf("MainStatus = %q; want 'Ready'", state.MainStatus)
	}
}

func TestStateResetUI(t *testing.T) {
	state := mustNewState(t)

	// Set progress-related flags
	state.Working = true
	state.ShowProgress = true
	state.CanCancel = true

	// Set other state
	state.Mode = "encrypt"
	state.Password = "secret"

	// ResetUI should NOT reset progress flags
	state.ResetUI()

	// Note: Working is reset by ResetUI based on the code

	// Other state should be reset
	if state.Mode != "" {
		t.Errorf("Mode = %q; want empty", state.Mode)
	}
	if state.Password != "" {
		t.Error("Password should be empty")
	}
}

func TestStateResetAfterOperation(t *testing.T) {
	state := mustNewState(t)

	state.Working = true
	state.ShowProgress = true
	state.CanCancel = true
	state.Progress = 0.75
	state.ProgressInfo = "75%"

	state.ResetAfterOperation()

	if state.Working {
		t.Error("Working should be false")
	}
	if state.ShowProgress {
		t.Error("ShowProgress should be false")
	}
	if state.CanCancel {
		t.Error("CanCancel should be false")
	}
	if state.Progress != 0 {
		t.Errorf("Progress = %f; want 0", state.Progress)
	}
	if state.ProgressInfo != "" {
		t.Errorf("ProgressInfo = %q; want empty", state.ProgressInfo)
	}
}

func TestIsEncryptingDecrypting(t *testing.T) {
	state := mustNewState(t)

	// Initially neither
	if state.IsEncrypting() {
		t.Error("Should not be encrypting initially")
	}
	if state.IsDecrypting() {
		t.Error("Should not be decrypting initially")
	}

	// Set encrypt mode
	state.Mode = "encrypt"
	if !state.IsEncrypting() {
		t.Error("Should be encrypting")
	}
	if state.IsDecrypting() {
		t.Error("Should not be decrypting in encrypt mode")
	}

	// Set decrypt mode
	state.Mode = "decrypt"
	if state.IsEncrypting() {
		t.Error("Should not be encrypting in decrypt mode")
	}
	if !state.IsDecrypting() {
		t.Error("Should be decrypting")
	}
}

func TestCanStart(t *testing.T) {
	state := mustNewState(t)

	// No credentials
	if state.CanStart() {
		t.Error("Should not be able to start without credentials")
	}

	// With password only
	state.Password = "secret"
	if !state.CanStart() {
		t.Error("Should be able to start with password")
	}

	// With keyfiles only
	state.Password = ""
	state.Keyfiles = []string{"keyfile.bin"}
	if !state.CanStart() {
		t.Error("Should be able to start with keyfiles")
	}

	// Encrypt mode with mismatched passwords
	state.Mode = "encrypt"
	state.Password = "secret"
	state.CPassword = "different"
	if state.CanStart() {
		t.Error("Should not be able to start with mismatched passwords")
	}

	// Encrypt mode with matching passwords
	state.CPassword = "secret"
	if !state.CanStart() {
		t.Error("Should be able to start with matching passwords")
	}

	// Decrypt mode ignores CPassword
	state.Mode = "decrypt"
	state.CPassword = "different"
	if !state.CanStart() {
		t.Error("Decrypt mode should not check password confirmation")
	}
}

func TestTogglePasswordVisibility(t *testing.T) {
	state := mustNewState(t)

	// Initially hidden
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should start hidden")
	}
	if state.PasswordStateLabel != "Show" {
		t.Error("Label should be 'Show'")
	}

	// Toggle to visible
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeVisible {
		t.Error("Should be visible after toggle")
	}
	if state.PasswordStateLabel != "Hide" {
		t.Error("Label should be 'Hide'")
	}

	// Toggle back to hidden
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeHidden {
		t.Error("Should be hidden after second toggle")
	}
	if state.PasswordStateLabel != "Show" {
		t.Error("Label should be 'Show'")
	}
}

func TestIsPasswordHidden(t *testing.T) {
	state := mustNewState(t)

	if !state.IsPasswordHidden() {
		t.Error("Password should be hidden initially")
	}

	state.PasswordMode = PasswordModeVisible
	if state.IsPasswordHidden() {
		t.Error("Password should not be hidden when visible")
	}
}

func TestUpdateKeyfileLabel(t *testing.T) {
	state := mustNewState(t)

	// No keyfiles, not required
	state.Keyfile = false
	state.Keyfiles = nil
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "None selected" {
		t.Errorf("KeyfileLabel = %q; want 'None selected'", state.KeyfileLabel)
	}

	// No keyfiles, but required
	state.Keyfile = true
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Keyfiles required" {
		t.Errorf("KeyfileLabel = %q; want 'Keyfiles required'", state.KeyfileLabel)
	}

	// One keyfile
	state.Keyfiles = []string{"key1.bin"}
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Using 1 keyfile" {
		t.Errorf("KeyfileLabel = %q; want 'Using 1 keyfile'", state.KeyfileLabel)
	}

	// Multiple keyfiles
	state.Keyfiles = []string{"key1.bin", "key2.bin", "key3.bin"}
	state.UpdateKeyfileLabel()
	if state.KeyfileLabel != "Using multiple keyfiles" {
		t.Errorf("KeyfileLabel = %q; want 'Using multiple keyfiles'", state.KeyfileLabel)
	}
}

func TestSetStatus(t *testing.T) {
	state := mustNewState(t)

	state.SetStatus("Testing", util.GREEN)

	if state.MainStatus != "Testing" {
		t.Errorf("MainStatus = %q; want 'Testing'", state.MainStatus)
	}
	if state.MainStatusColor != util.GREEN {
		t.Error("MainStatusColor should be GREEN")
	}
}

func TestSetPopupStatus(t *testing.T) {
	state := mustNewState(t)

	state.SetPopupStatus("Processing...")

	if state.PopupStatus != "Processing..." {
		t.Errorf("PopupStatus = %q; want 'Processing...'", state.PopupStatus)
	}
}

func TestSetProgress(t *testing.T) {
	state := mustNewState(t)

	state.SetProgress(0.5, "50%")

	if state.Progress != 0.5 {
		t.Errorf("Progress = %f; want 0.5", state.Progress)
	}
	if state.ProgressInfo != "50%" {
		t.Errorf("ProgressInfo = %q; want '50%%'", state.ProgressInfo)
	}
}

func TestSetCanCancel(t *testing.T) {
	state := mustNewState(t)

	state.SetCanCancel(true)
	if !state.CanCancel {
		t.Error("CanCancel should be true")
	}

	state.SetCanCancel(false)
	if state.CanCancel {
		t.Error("CanCancel should be false")
	}
}

func TestGenPassword(t *testing.T) {
	state := mustNewState(t)

	// Set passgen options
	state.PassgenLength = 20
	state.PassgenUpper = true
	state.PassgenLower = true
	state.PassgenNums = true
	state.PassgenSymbols = false
	state.PassgenCopy = false

	password := state.GenPassword()

	if len(password) != 20 {
		t.Errorf("Password length = %d; want 20", len(password))
	}

	// Should not contain symbols
	for _, ch := range password {
		if ch == '-' || ch == '=' || ch == '_' || ch == '+' || ch == '!' {
			t.Error("Password should not contain symbols")
		}
	}
}

func TestGenPasswordNoOptions(t *testing.T) {
	state := mustNewState(t)

	// No character sets enabled
	state.PassgenLength = 10
	state.PassgenUpper = false
	state.PassgenLower = false
	state.PassgenNums = false
	state.PassgenSymbols = false
	state.PassgenCopy = false

	password := state.GenPassword()

	if password != "" {
		t.Errorf("Password = %q; want empty when no char sets", password)
	}
}

// TestStateWorkerCallbackConcurrency models the APP-02 worker↔render boundary:
// one set of goroutines plays the encrypt/decrypt worker (reading the request
// fields via Snapshot() and writing status/result via the locked setters), while
// another set plays the Fyne render-thread callbacks (reading/writing the same
// fields via the locked getters/setters). It must be clean under `go test -race`
// — it is the project-code race the APP-02 gate keeps green (D-06).
//
// This test will not compile until State grows Snapshot() plus the missing
// locked accessors (Mode/Working/InputFile/OutputFile/Comments/Deniability/
// Keep/Kept). That non-compiling state is the RED phase.
func TestStateWorkerCallbackConcurrency(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatalf("NewState() error: %v", err)
	}

	const iterations = 200
	var wg sync.WaitGroup

	// Worker goroutine: build a request snapshot under one RLock, then write
	// status/result through the locked setters — exactly the operations.go
	// doEncrypt/doDecrypt hot-path access pattern.
	wg.Go(func() {
		for i := range iterations {
			snap := state.Snapshot()
			// Touch the snapshot fields so the race detector sees the reads.
			_ = snap.Mode
			_ = snap.InputFile
			_ = snap.OutputFile
			_ = snap.Password
			_ = snap.Keyfiles
			_ = snap.Comments
			_ = snap.Paranoid
			_ = snap.ReedSolomon
			_ = snap.Deniability
			_ = snap.Compress
			_ = snap.VerifyFirst
			_ = snap.Keep
			state.SetStatus("working", util.WHITE)
			state.SetKept(i%2 == 0)
		}
	})

	// Render-thread callback goroutine: drives the locked setters the drop /
	// operations callbacks use to mutate shared fields concurrently.
	wg.Go(func() {
		for i := range iterations {
			state.SetMode("encrypt")
			state.SetWorking(i%2 == 0)
			state.SetInputFile("in.txt")
			state.SetOutputFile("out.pcv")
			state.SetComments("hello")
			state.SetDeniability(i%2 == 0)
			state.SetKeep(i%2 == 1)
		}
	})

	// Render-thread reader goroutine: hits the locked getters concurrently.
	wg.Go(func() {
		for range iterations {
			_ = state.IsEncrypting()
			_ = state.IsDecrypting()
			_ = state.IsWorking()
			rsnap := state.Snapshot()
			_ = rsnap.InputFile
			_ = rsnap.OutputFile
			_ = rsnap.Comments
			_ = rsnap.Deniability
			_ = rsnap.Keep
			_ = state.WasKept()
		}
	})

	wg.Wait()

	// Sanity: the accessors round-trip a written value consistently.
	state.SetMode("decrypt")
	if !state.IsDecrypting() {
		t.Fatal("IsDecrypting() = false after SetMode(\"decrypt\")")
	}
	state.SetWorking(true)
	if !state.IsWorking() {
		t.Fatal("IsWorking() = false after SetWorking(true)")
	}
}

func TestStateConcurrency(t *testing.T) {
	state := mustNewState(t)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads
	wg.Add(iterations)
	for range iterations {
		go func() {
			defer wg.Done()
			_ = state.IsEncrypting()
			_ = state.IsDecrypting()
			_ = state.CanStart()
			_ = state.IsPasswordHidden()
		}()
	}

	// Concurrent writes
	wg.Add(iterations)
	for i := range iterations {
		go func(i int) {
			defer wg.Done()
			state.SetStatus("Test", util.WHITE)
			state.SetPopupStatus("Status")
			state.SetProgress(float32(i)/float32(iterations), "")
			state.SetCanCancel(i%2 == 0)
			state.TogglePasswordVisibility()
			state.UpdateKeyfileLabel()
		}(i)
	}

	wg.Wait()
	t.Log("Concurrent access completed without deadlock")
}

// TestPasswordInputModeConstants verifies the named PasswordInputMode constants
// are wired correctly into their consumers, rather than asserting the trivial
// iota distinctness (0 != 1). It pins two bindings: NewState initializes
// PasswordMode to PasswordModeHidden, and IsPasswordHidden tracks the named
// constant at each value. This catches a consumer that hard-codes a literal or
// returns a constant answer.
//
// Residual overlap with TestIsPasswordHidden is minimal and intentional: that
// test exercises IsPasswordHidden in isolation, while this one ties the named
// constants to both the constructor default and the predicate together — the
// binding the original tautology failed to assert.
func TestPasswordInputModeConstants(t *testing.T) {
	state := mustNewState(t)

	// Constructor default is bound to the named constant, not a bare literal.
	if state.PasswordMode != PasswordModeHidden {
		t.Errorf("NewState PasswordMode = %d; want PasswordModeHidden (%d)", state.PasswordMode, PasswordModeHidden)
	}
	if !state.IsPasswordHidden() {
		t.Error("IsPasswordHidden() = false at PasswordModeHidden; want true")
	}

	// One toggle flips to the visible constant; the predicate must follow it.
	state.TogglePasswordVisibility()
	if state.PasswordMode != PasswordModeVisible {
		t.Errorf("after toggle PasswordMode = %d; want PasswordModeVisible (%d)", state.PasswordMode, PasswordModeVisible)
	}
	if state.IsPasswordHidden() {
		t.Error("IsPasswordHidden() = true at PasswordModeVisible; want false")
	}
}

// TestStateVersion is a desync tripwire, not a tautology: it asserts the
// app.Version const stays in lockstep with the canonical root VERSION file
// (app.Version must be "v" + <VERSION>). A version bump that edits VERSION but
// forgets state.go (or vice versa) fails here. This is non-duplicative of
// distmeta's TestActiveReleaseMetadataVersions, which validates VERSION against
// distribution metadata but never references app.Version.
func TestStateVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "VERSION"))
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	want := "v" + strings.TrimSpace(string(raw))
	if Version != want {
		t.Fatalf("app.Version = %q; want %q (derived from root VERSION file)", Version, want)
	}
}
