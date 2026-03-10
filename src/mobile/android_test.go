package mobile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"Picocrypt-NG/internal/volume"
)

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
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON)); got != "" {
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
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartEncrypt(string(reqJSON)); !strings.Contains(got, "input file is required") {
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
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON)); !strings.Contains(got, "input file is required") {
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
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON)); got != "" {
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
		Password:    "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := StartDecrypt(string(reqJSON)); got != "" {
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
