package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestVersionFlagOutputsV213 drives the REAL cli.Execute(version) entrypoint with
// os.Args set to {bin, "--version"} and asserts the passed version reaches cobra's
// stdout. This exercises the runtime wiring rootCmd.Version = version in Execute()
// (root.go:124); deleting that line leaves rootCmd.Version stale ("dev") and turns
// this red. The former test pre-assigned rootCmd.Version to the asserted literal
// and called rootCmd.Execute() directly, so it never touched the production wiring.
func TestVersionFlagOutputsV213(t *testing.T) {
	const want = "v2.13"

	oldVersion := Version
	oldRootVersion := rootCmd.Version
	oldArgs := os.Args
	oldStdout := os.Stdout
	t.Cleanup(func() {
		Version = oldVersion
		rootCmd.Version = oldRootVersion
		os.Args = oldArgs
		os.Stdout = oldStdout
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	// Reset to a stale sentinel so that if the production wiring
	// (rootCmd.Version = version, root.go:124) is removed, the stale value leaks.
	rootCmd.Version = "dev"
	rootCmd.SetArgs(nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	os.Args = []string{"picocrypt", "--version"}

	if cliMode := Execute(want); !cliMode {
		_ = w.Close()
		os.Stdout = oldStdout
		t.Fatal("Execute(--version) returned false; CLI mode should be active")
	}

	_ = w.Close()
	os.Stdout = oldStdout

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	_ = r.Close()

	got := out.String()
	if !strings.Contains(got, want) {
		t.Fatalf("--version output = %q; want it to contain %q", got, want)
	}
	if rootCmd.Version != want {
		t.Fatalf("rootCmd.Version = %q after Execute(%q); want %q", rootCmd.Version, want, want)
	}
	if strings.Contains(got, "dev") {
		t.Fatalf("--version output = %q; must not contain stale \"dev\"", got)
	}
}
