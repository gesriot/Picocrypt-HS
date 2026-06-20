package main

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/cli"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test working directory to the repository root,
// identified as the directory holding both the VERSION file and
// .github/workflows. Duplicating this helper per package matches the codebase
// convention (see internal/app/state_test.go, internal/distmeta/distmeta_test.go).
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

// TestRuntimeVersionMatchesAppVersion pins BOTH the cmd-level runtime version
// const and app.Version to the canonical root VERSION file (with the "v" prefix
// the code uses). This makes the root VERSION file the single source of truth:
// if either literal drifts from VERSION, this test turns red.
//
// Mutation: bumping the root VERSION file without updating cmd version, or
// updating one of the two literals but not the other, would fail this test.
func TestRuntimeVersionMatchesAppVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "VERSION"))
	if err != nil {
		t.Fatalf("read root VERSION file: %v", err)
	}
	want := "v" + strings.TrimSpace(string(raw))

	if version != want {
		t.Fatalf("cmd version = %q; want %q (single source: root VERSION file)", version, want)
	}
	if app.Version != want {
		t.Fatalf("app.Version = %q; want %q (single source: root VERSION file)", app.Version, want)
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
