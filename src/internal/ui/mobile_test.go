package ui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type closeTrackingReadCloser struct {
	reader io.Reader
	closed bool
}

func (r *closeTrackingReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *closeTrackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type bytesThenErrorReadCloser struct {
	data   []byte
	err    error
	read   bool
	closed bool
}

func (r *bytesThenErrorReadCloser) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	return copy(p, r.data), r.err
}

func (r *bytesThenErrorReadCloser) Close() error {
	r.closed = true
	return nil
}

type coordinatedCancelReadCloser struct {
	data              []byte
	reads             int
	secondReadStarted chan struct{}
	continueRead      chan struct{}
	releaseOnce       sync.Once
	closed            bool
}

func (r *coordinatedCancelReadCloser) Read(p []byte) (int, error) {
	switch r.reads {
	case 0:
		r.reads++
		return copy(p, r.data), nil
	case 1:
		r.reads++
		close(r.secondReadStarted)
		<-r.continueRead
		return 0, nil
	default:
		return 0, io.EOF
	}
}

func (r *coordinatedCancelReadCloser) Close() error {
	r.closed = true
	return nil
}

func (r *coordinatedCancelReadCloser) release() {
	r.releaseOnce.Do(func() {
		close(r.continueRead)
	})
}

func TestValidateMobileTempFilename(t *testing.T) {
	testCases := []struct {
		name    string
		wantErr bool
	}{
		{name: "photo.jpg", wantErr: false},
		{name: "archive..bak", wantErr: false},
		{name: "", wantErr: true},
		{name: ".", wantErr: true},
		{name: "..", wantErr: true},
		{name: "../evil", wantErr: true},
		{name: `..\evil`, wantErr: true},
		{name: "dir/file.txt", wantErr: true},
		{name: `dir\file.txt`, wantErr: true},
		{name: "/abs", wantErr: true},
		{name: `C:\abs`, wantErr: true},
		{name: ".. ", wantErr: true},
		{name: ".. .", wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMobileTempFilename(tc.name)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateMobileTempFilename(%q) error = %v, wantErr %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestCopyURIToTempRejectsUnsafeFilename(t *testing.T) {
	root := t.TempDir()
	tempDir := filepath.Join(root, "mobile")
	reader := &closeTrackingReadCloser{reader: strings.NewReader("payload")}

	escapePath := filepath.Clean(filepath.Join(tempDir, "..", "escape.txt"))
	if err := os.WriteFile(escapePath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write escape sentinel: %v", err)
	}

	_, err := copyURIToTemp(context.Background(), tempDir, reader, "../escape.txt")
	if !errors.Is(err, errUnsafeMobileFilename) {
		t.Fatalf("copyURIToTemp error = %v, want %v", err, errUnsafeMobileFilename)
	}
	if !reader.closed {
		t.Fatal("copyURIToTemp did not close the rejected source")
	}

	data, readErr := os.ReadFile(escapePath)
	if readErr != nil {
		t.Fatalf("read escape sentinel: %v", readErr)
	}
	if string(data) != "original" {
		t.Fatalf("escape sentinel overwritten: %q", data)
	}
}

func TestCopyURIToTempAcceptsSafeFilename(t *testing.T) {
	tempDir := t.TempDir()
	reader := &closeTrackingReadCloser{reader: strings.NewReader("payload")}

	got, err := copyURIToTemp(context.Background(), tempDir, reader, "photo.jpg")
	if err != nil {
		t.Fatalf("copyURIToTemp failed: %v", err)
	}
	if !reader.closed {
		t.Fatal("copyURIToTemp did not close the copied source")
	}

	want := filepath.Join(tempDir, "photo.jpg")
	if got != want {
		t.Fatalf("copyURIToTemp path = %q, want %q", got, want)
	}

	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("copied file content = %q", data)
	}
}

func TestCopyURIToTempCancelRemovesPartialDestination(t *testing.T) {
	tempDir := t.TempDir()
	reader := &coordinatedCancelReadCloser{
		data:              []byte("first chunk"),
		secondReadStarted: make(chan struct{}),
		continueRead:      make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	destPath := filepath.Join(tempDir, "cancelled.bin")

	type result struct {
		path string
		err  error
	}
	resultCh := make(chan result, 1)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		path, err := copyURIToTemp(ctx, tempDir, reader, "cancelled.bin")
		resultCh <- result{path: path, err: err}
	}()
	t.Cleanup(func() {
		cancel()
		reader.release()
		<-workerDone
	})

	select {
	case <-reader.secondReadStarted:
	case got := <-resultCh:
		t.Fatalf("copyURIToTemp returned before cancellation: path %q, error %v", got.path, got.err)
	}
	partial, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read partial destination before cancellation: %v", err)
	}
	if string(partial) != "first chunk" {
		t.Fatalf("partial destination before cancellation = %q, want %q", partial, "first chunk")
	}
	cancel()
	reader.release()
	got := <-resultCh

	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("copyURIToTemp error = %v, want %v", got.err, context.Canceled)
	}
	if got.path != "" {
		t.Fatalf("copyURIToTemp path = %q after cancellation, want empty", got.path)
	}
	if !reader.closed {
		t.Fatal("copyURIToTemp did not close the cancelled source")
	}
	if _, err := os.Stat(destPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination still exists after cancellation: %v", err)
	}
}

func TestCopyURIToTempReadErrorRemovesPartialDestination(t *testing.T) {
	tempDir := t.TempDir()
	wantErr := errors.New("provider read failed")
	reader := &bytesThenErrorReadCloser{
		data: []byte("partial payload"),
		err:  wantErr,
	}

	got, err := copyURIToTemp(context.Background(), tempDir, reader, "failed.bin")

	if !errors.Is(err, wantErr) {
		t.Fatalf("copyURIToTemp error = %v, want %v", err, wantErr)
	}
	if got != "" {
		t.Fatalf("copyURIToTemp path = %q after read error, want empty", got)
	}
	if !reader.closed {
		t.Fatal("copyURIToTemp did not close the failed source")
	}
	destPath := filepath.Join(tempDir, "failed.bin")
	if _, err := os.Stat(destPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination still exists after read error: %v", err)
	}
}
