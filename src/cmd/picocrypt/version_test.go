package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/cli"
)

// Version-agnostic by design: it pins the runtime version const to app.Version,
// which TestStateVersion ties to the canonical root VERSION file. A release bump
// edits the version literals only -- this test never needs renaming or re-bumping.
func TestRuntimeVersionMatchesAppVersion(t *testing.T) {
	if version != app.Version {
		t.Fatalf("cmd version = %q; want app.Version %q (single source: root VERSION file)", version, app.Version)
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
	if !strings.Contains(got, version) {
		t.Fatalf("CLI --version output = %q; want it to contain the runtime version %q", got, version)
	}
	if strings.Contains(got, "dev") {
		t.Fatalf("CLI --version output = %q; must not contain cobra's default %q (version wiring missing)", got, "dev")
	}
}
