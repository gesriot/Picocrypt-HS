package workflowpolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, ".github", "workflows")); err == nil {
			return current
		}

		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("could not find repository root from test working directory")
		}
		current = parent
	}
}

func mustReadWorkflow(t *testing.T, relPath string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read workflow %s: %v", relPath, err)
	}
	return string(content)
}

func mustContain(t *testing.T, content, substring string) {
	t.Helper()

	if !strings.Contains(content, substring) {
		t.Fatalf("expected workflow to contain %q", substring)
	}
}

func mustNotContain(t *testing.T, content, substring string) {
	t.Helper()

	if strings.Contains(content, substring) {
		t.Fatalf("expected workflow not to contain %q", substring)
	}
}

func mustMatch(t *testing.T, content, pattern string) {
	t.Helper()

	matched, err := regexp.MatchString(pattern, content)
	if err != nil {
		t.Fatalf("compile pattern %q: %v", pattern, err)
	}
	if !matched {
		t.Fatalf("expected workflow to match %q", pattern)
	}
}
