package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"Picocrypt-NG/internal/cli"
)

func TestRuntimeVersionIsV210(t *testing.T) {
	if version != "v2.10" {
		t.Fatalf("version = %q; want %q", version, "v2.10")
	}
}

func TestRuntimeVersionFeedsCLIVersionOutput(t *testing.T) {
	oldArgs := os.Args
	oldStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	os.Args = []string{"Picocrypt-NG", "--version"}

	activated := cli.Execute(version)

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	os.Stdout = oldStdout

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}

	if !activated {
		t.Fatal("cli.Execute(version) did not activate CLI mode for --version")
	}

	got := out.String()
	if !strings.Contains(got, "v2.10") {
		t.Fatalf("CLI --version output = %q; want it to contain %q", got, "v2.10")
	}
	if strings.Contains(got, "v2.09") {
		t.Fatalf("CLI --version output = %q; must not contain stale v2.09", got)
	}
}
