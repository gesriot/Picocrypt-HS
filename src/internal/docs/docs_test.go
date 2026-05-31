package docs

import (
	"os"
	"path/filepath"
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

func mustReadDoc(t *testing.T, relPath string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repoRoot(t), relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}

func TestWASMDocumentationStatesReducedSurfaceAndZeroingLimits(t *testing.T) {
	docs := map[string]string{
		"web README":   mustReadDoc(t, "README.md"),
		"build README": mustReadDoc(t, "src/README.md"),
	}

	requiredSnippets := []string{
		"standard password-only single-file volumes",
		"Paranoid mode",
		"keyfiles",
		"Reed-Solomon payload protection",
		"splitting",
		"deniability",
		"Go-owned byte buffers are wiped best-effort",
		"JavaScript engine",
		"garbage-collected runtime copies cannot be guaranteed wiped",
	}

	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			for _, snippet := range requiredSnippets {
				if !strings.Contains(doc, snippet) {
					t.Errorf("missing %q", snippet)
				}
			}
		})
	}
}
