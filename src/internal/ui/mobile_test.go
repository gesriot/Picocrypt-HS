package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	a := createTestApp(t)
	filesDir := t.TempDir()
	t.Setenv("FILESDIR", filesDir)

	escapePath := filepath.Clean(filepath.Join(a.getMobileTempDir(), "..", "escape.txt"))
	if err := os.WriteFile(escapePath, []byte("original"), 0o600); err != nil {
		t.Fatalf("write escape sentinel: %v", err)
	}

	_, err := a.copyURIToTemp(strings.NewReader("payload"), "../escape.txt")
	if err == nil {
		t.Fatal("copyURIToTemp should reject traversal-like file names")
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
	a := createTestApp(t)
	filesDir := t.TempDir()
	t.Setenv("FILESDIR", filesDir)

	got, err := a.copyURIToTemp(strings.NewReader("payload"), "photo.jpg")
	if err != nil {
		t.Fatalf("copyURIToTemp failed: %v", err)
	}

	want := filepath.Join(a.getMobileTempDir(), "photo.jpg")
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
