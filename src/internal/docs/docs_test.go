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

func TestWASMDocumentationStatesCurrentSurfaceAndZeroingLimits(t *testing.T) {
	docs := map[string]string{
		"web README":   mustReadDoc(t, "README.md"),
		"build README": mustReadDoc(t, "src/README.md"),
	}

	requiredSnippets := []string{
		"in-memory single-file encryption and decryption",
		"WASM bridge caps inputs at 1 GiB",
		"supports comments, Paranoid mode, keyfiles, Reed-Solomon payload protection, force decrypt, and deniability",
		"non-streaming and single-file oriented",
		"folder workflows, split volumes, and large streaming jobs remain desktop/CLI/native-app features",
		"Go-owned byte buffers are wiped best-effort",
		"JavaScript engine copies",
		"garbage-collected runtime copies cannot be guaranteed wiped",
	}
	forbiddenSnippets := []string{
		"standard password-only single-file volumes",
		"does not enable Paranoid mode, keyfiles, Reed-Solomon payload protection, splitting, or deniability",
	}

	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			for _, snippet := range requiredSnippets {
				if !strings.Contains(doc, snippet) {
					t.Errorf("missing %q", snippet)
				}
			}
			for _, snippet := range forbiddenSnippets {
				if strings.Contains(doc, snippet) {
					t.Errorf("contains stale WASM wording %q", snippet)
				}
			}
		})
	}
}

func TestCLIForceDecryptDocumentationStatesKeptOutputExitSemantics(t *testing.T) {
	doc := mustReadDoc(t, "CLI.md")

	requiredSnippets := []string{
		"--force",
		"exit code 2",
		"stderr",
		"Warning: Force decrypt kept output",
		"not fully verified",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(doc, snippet) {
			t.Errorf("missing %q", snippet)
		}
	}
}
