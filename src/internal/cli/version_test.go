package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlagOutputsV210(t *testing.T) {
	const want = "v2.10"

	oldVersion := Version
	oldRootVersion := rootCmd.Version
	t.Cleanup(func() {
		Version = oldVersion
		rootCmd.Version = oldRootVersion
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	Version = want
	rootCmd.Version = want

	var out bytes.Buffer
	rootCmd.SetArgs([]string{"--version"})
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("rootCmd.Execute() error = %v", err)
	}

	got := out.String()
	if !strings.Contains(got, want) {
		t.Fatalf("--version output = %q; want it to contain %q", got, want)
	}
	if strings.Contains(got, "v2.09") {
		t.Fatalf("--version output = %q; must not contain stale v2.09", got)
	}
}
