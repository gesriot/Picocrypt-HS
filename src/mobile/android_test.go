package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	perrors "Picocrypt-NG/internal/errors"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/volume"
)

// TestErrorCodeFor pins the pipeline-error -> stable-code mapping the Android
// layer relies on to gate force-decrypt (corruption-only) and password-retry
// (auth-only). The mapping is security-relevant: misclassifying a wrong-password
// (*header.AuthError) as corruption would wrongly offer force-decrypt, which
// BYPASSES integrity/RS checks. Each case wraps the real error value with %w to
// prove errors.Is/As classification survives wrapping (as it does through the
// pipeline's fmt.Errorf("...: %w", err) chains).
func TestErrorCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil is no error", err: nil, want: ""},
		// Normal decrypt path: wrong password/keyfile surfaces as *header.AuthError
		// (decrypt.go:273,283,335,345). It does NOT wrap perrors.ErrAuthFailed, so
		// errors.Is(ErrAuthFailed) alone would miss it; errorCode uses errors.As.
		{name: "v2 password-or-tamper AuthError", err: header.NewV2PasswordOrTamperError(), want: "AUTH_FAILED"},
		{name: "v1 password AuthError", err: header.NewPasswordError(), want: "AUTH_FAILED"},
		{name: "keyfile AuthError", err: header.NewKeyfileError(true), want: "AUTH_FAILED"},
		{name: "wrapped AuthError", err: fmt.Errorf("decrypt: %w", header.NewPasswordError()), want: "AUTH_FAILED"},
		// Verify-first path returns the bare sentinel (decrypt.go:572).
		{name: "ErrAuthFailed sentinel", err: perrors.ErrAuthFailed, want: "AUTH_FAILED"},
		{name: "wrapped ErrAuthFailed", err: fmt.Errorf("verify: %w", perrors.ErrAuthFailed), want: "AUTH_FAILED"},
		// Payload corruption RS cannot recover (decrypt.go:796 and decodeWithRSFast).
		{name: "ErrCorruptData sentinel", err: perrors.ErrCorruptData, want: "DATA_CORRUPTED"},
		{name: "wrapped ErrCorruptData", err: fmt.Errorf("finalize: %w", perrors.ErrCorruptData), want: "DATA_CORRUPTED"},
		// Header damage: decrypt.go:204 wraps header.ErrCorruptedHeader. Must NOT
		// be DATA_CORRUPTED (old logic excluded header) -> CORRUPT_HEADER (not
		// force-decryptable on the Kotlin side).
		{name: "header damaged wraps ErrCorruptedHeader", err: fmt.Errorf("header damaged: %w", header.ErrCorruptedHeader), want: "CORRUPT_HEADER"},
		{name: "ErrCorruptHeader sentinel", err: perrors.ErrCorruptHeader, want: "CORRUPT_HEADER"},
		{name: "ErrFileNotFound sentinel", err: perrors.ErrFileNotFound, want: "FILE_NOT_FOUND"},
		{name: "wrapped ErrFileNotFound", err: fmt.Errorf("open: %w", perrors.ErrFileNotFound), want: "FILE_NOT_FOUND"},
		{name: "ErrCancelled sentinel", err: perrors.ErrCancelled, want: "CANCELLED"},
		// Auth must win over corruption when both are in the chain, mirroring the
		// old substring logic (auth checked before/over corruption).
		{name: "auth wins over corruption", err: fmt.Errorf("%w: %w", perrors.ErrAuthFailed, perrors.ErrCorruptData), want: "AUTH_FAILED"},
		{name: "unknown error is generic", err: fmt.Errorf("something unexpected"), want: "GENERIC"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorCode(tc.err); got != tc.want {
				t.Errorf("errorCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func resetProgressMap() {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	globalProgressMap.ops = make(map[string]*ProgressState)
	globalProgressMap.ctxs = make(map[string]context.Context)
	globalProgressMap.cancels = make(map[string]context.CancelFunc)
}

func TestDetectOperation(t *testing.T) {
	t.Cleanup(resetProgressMap)

	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{name: "pcv file decrypts", filename: "sample.txt.pcv", want: false},
		{name: "split volume decrypts", filename: "archive.zip.pcv.0", want: false},
		{name: "false positive backup stays encrypt", filename: "backup.pcv.tmp1", want: true},
		{name: "false positive version stays encrypt", filename: "notes.pcv.v2", want: true},
		{name: "plain file encrypts", filename: "plain.txt", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.filename)
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := DetectOperation(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("DetectOperation(%q) = %v, want %v", path, got, tc.want)
			}
		})
	}
}

func TestCompleteOperationDoesNotOverwriteCancelledState(t *testing.T) {
	resetProgressMap()

	id, _, _ := startOperation()
	if err := cancelOperation(id); err != nil {
		t.Fatal(err)
	}

	completeOperation(id, nil)

	state, err := getProgress(id)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "Cancelled" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Cancelled")
	}
	if !state.Done {
		t.Fatalf("cancelled operation should remain done")
	}
}

func TestStartEncryptFailsWhenOperationContextIsMissing(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(inputPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "plain.txt.pcv")
	id := StartOperation()

	globalProgressMap.mu.Lock()
	delete(globalProgressMap.ctxs, id)
	globalProgressMap.mu.Unlock()

	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartEncrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "context") {
		t.Fatalf("state.Error = %q, want context-related error", state.Error)
	}
}

func TestStartEncryptValidationFailureCleansUpOperation(t *testing.T) {
	resetProgressMap()

	id := StartOperation()
	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFile:   "",
		OutputFile:  "out.pcv",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON), []byte("password")); !strings.Contains(got, "input file is required") {
		t.Fatalf("StartEncrypt(...) = %q", got)
	}

	globalProgressMap.mu.RLock()
	_, opExists := globalProgressMap.ops[id]
	_, ctxExists := globalProgressMap.ctxs[id]
	_, cancelExists := globalProgressMap.cancels[id]
	globalProgressMap.mu.RUnlock()

	if opExists || ctxExists || cancelExists {
		t.Fatalf("validation failure leaked operation state: op=%v ctx=%v cancel=%v", opExists, ctxExists, cancelExists)
	}
}

func TestStartDecryptValidationFailureCleansUpOperation(t *testing.T) {
	resetProgressMap()

	id := StartOperation()
	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   "",
		OutputFile:  "out",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); !strings.Contains(got, "input file is required") {
		t.Fatalf("StartDecrypt(...) = %q", got)
	}

	globalProgressMap.mu.RLock()
	_, opExists := globalProgressMap.ops[id]
	_, ctxExists := globalProgressMap.ctxs[id]
	_, cancelExists := globalProgressMap.cancels[id]
	globalProgressMap.mu.RUnlock()

	if opExists || ctxExists || cancelExists {
		t.Fatalf("validation failure leaked operation state: op=%v ctx=%v cancel=%v", opExists, ctxExists, cancelExists)
	}
}

func TestStartDecryptFailsWhenOperationContextIsMissing(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "sample.txt.pcv")
	if err := os.WriteFile(inputPath, []byte("not-a-real-volume"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "sample.txt")
	id := StartOperation()

	globalProgressMap.mu.Lock()
	delete(globalProgressMap.ctxs, id)
	globalProgressMap.mu.Unlock()

	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartDecrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "context") {
		t.Fatalf("state.Error = %q, want context-related error", state.Error)
	}
}

func TestStartDecryptRecoversPanic(t *testing.T) {
	resetProgressMap()

	inputPath := filepath.Join(t.TempDir(), "sample.txt.pcv")
	if err := os.WriteFile(inputPath, []byte("not-a-real-volume"), 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), "sample.txt")
	id := StartOperation()

	orig := runDecrypt
	runDecrypt = func(context.Context, *volume.DecryptRequest) error {
		panic("boom")
	}
	defer func() { runDecrypt = orig }()

	reqJSON, err := json.Marshal(DecryptRequestJSON{
		OperationID: id,
		InputFile:   inputPath,
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON), []byte("password")); got != "" {
		t.Fatalf("StartDecrypt(...) returned %q, want empty string", got)
	}

	state := waitForDone(t, id)
	if state.Status != "Error" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "Error")
	}
	if !strings.Contains(state.Error, "panic: boom") {
		t.Fatalf("state.Error = %q, want panic error", state.Error)
	}
}

func TestStartEncryptZeroesPasswordBytes(t *testing.T) {
	resetProgressMap()
	inputPath := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(inputPath, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(t.TempDir(), "plain.txt.pcv")
	id := StartOperation()

	orig := runEncrypt
	runEncrypt = func(context.Context, *volume.EncryptRequest) error { return nil }
	defer func() { runEncrypt = orig }()

	reqJSON, err := json.Marshal(EncryptRequestJSON{OperationID: id, InputFile: inputPath, OutputFile: outputPath})
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("hunter2")
	if got := StartEncrypt(string(reqJSON), password); got != "" {
		t.Fatalf("StartEncrypt(...) = %q, want empty", got)
	}
	for i, b := range password {
		if b != 0 {
			t.Fatalf("password[%d] = %d, want 0", i, b)
		}
	}
	_ = waitForDone(t, id)
}

func TestStartEncryptPassesMultiFileSelection(t *testing.T) {
	resetProgressMap()

	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outputPath := filepath.Join(dir, "out.pcv")

	var captured *volume.EncryptRequest
	orig := runEncrypt
	runEncrypt = func(_ context.Context, req *volume.EncryptRequest) error {
		captured = req
		return nil
	}
	defer func() { runEncrypt = orig }()

	id := StartOperation()
	reqJSON, err := json.Marshal(EncryptRequestJSON{
		OperationID: id,
		InputFiles:  []string{a, b},
		OnlyFiles:   []string{a, b},
		OnlyFolders: []string{dir},
		OutputFile:  outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := StartEncrypt(string(reqJSON), []byte("pw")); got != "" {
		t.Fatalf("StartEncrypt(...) = %q, want empty", got)
	}
	_ = waitForDone(t, id)

	if captured == nil {
		t.Fatal("runEncrypt was not called")
	}
	if len(captured.InputFiles) != 2 || captured.InputFiles[0] != a || captured.InputFiles[1] != b {
		t.Fatalf("InputFiles = %#v, want [%q %q]", captured.InputFiles, a, b)
	}
	if len(captured.OnlyFiles) != 2 {
		t.Fatalf("OnlyFiles = %#v, want 2 entries", captured.OnlyFiles)
	}
	if len(captured.OnlyFolders) != 1 || captured.OnlyFolders[0] != dir {
		t.Fatalf("OnlyFolders = %#v, want [%q]", captured.OnlyFolders, dir)
	}
	if captured.InputFile != "" {
		t.Fatalf("InputFile = %q, want empty for multi-file selection", captured.InputFile)
	}
}

func waitForDone(t *testing.T, id string) *ProgressState {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		state, err := getProgress(id)
		if err != nil {
			t.Fatal(err)
		}
		if state.Done {
			return state
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("operation %s did not complete before timeout", id)
	return nil
}
