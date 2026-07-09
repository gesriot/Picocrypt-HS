package ui

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var forbiddenCLILocalizationTokens = []string{
	"fyne.io/fyne/v2/lang",
	"translation/",
	"lang.X(",
	"lang.L(",
	"lang.N(",
	"lang.XN(",
}

var forbiddenCLILanguageControlTokens = []string{
	"ui.language",
	"setActiveLanguage",
	"SwitchLanguage",
	"LanguageCode",
	"languagePreferenceKey",
	"--language",
	"--locale",
	"Use: \"language",
	"Use: \"locale",
}

func TestCLIDoesNotUseLocalization(t *testing.T) {
	failures := collectCLILocalizationFailures(t)
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("CLI files must not depend on Fyne localization:\n%s", strings.Join(failures, "\n"))
	}
}

func TestCLIDoesNotExposeLanguageOrLocaleFlags(t *testing.T) {
	roots := []string{
		"../cli",
		"../../cmd/picocrypt",
	}

	var failures []string
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if filepath.Clean(root) == filepath.Clean("../../cmd/picocrypt") &&
				!shouldScanPicocryptEntryForCLILocalization(path, data) {
				return nil
			}
			failures = append(failures, collectForbiddenCLILanguageControlTokensFromSource(filepath.ToSlash(path), string(data))...)
			return nil
		}); err != nil {
			t.Fatalf("walk %s for CLI language flag guard: %v", root, err)
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("CLI must remain English-only and must not expose language controls:\n%s", strings.Join(failures, "\n"))
	}
}

func TestCLILanguageControlGuardDetectsForbiddenTokens(t *testing.T) {
	source := `package cli

func bad() {
	_ = "--language"
	_ = "--locale"
	_ = "ui.language"
	_ = "Use: \"language"
	_ = "Use: \"locale"
	_ = "setActiveLanguage"
	_ = "SwitchLanguage"
	_ = "LanguageCode"
	_ = "languagePreferenceKey"
}
`
	failures := collectForbiddenCLILanguageControlTokensFromSource("bad.go", source)
	failureText := strings.Join(failures, "\n")
	for _, token := range forbiddenCLILanguageControlTokens {
		if !strings.Contains(failureText, fmt.Sprintf("%q", token)) {
			t.Fatalf("guard did not report forbidden token %q in failures:\n%s", token, failureText)
		}
	}
}

func TestCLILocalizationGuardDetectsForbiddenTokens(t *testing.T) {
	source := `package cli

import "fyne.io/fyne/v2/lang"

func bad() {
	_ = "translation/en.json"
	_ = lang.X("x", "fallback")
	_ = lang.L("x")
	_ = lang.N("x", "fallback", 2)
	_ = lang.XN("x", "fallback", 2)
}
`
	failures := collectForbiddenCLILocalizationTokensFromSource("bad.go", source)
	failureText := strings.Join(failures, "\n")

	for _, token := range forbiddenCLILocalizationTokens {
		if !strings.Contains(failureText, fmt.Sprintf("%q", token)) {
			t.Fatalf("guard did not report forbidden token %q in failures:\n%s", token, failureText)
		}
	}
}

func TestCLILocalizationGuardScopesPicocryptEntryFiles(t *testing.T) {
	const guiOnlySource = "//go:build !cli\n\npackage main\n"

	tests := []struct {
		name string
		path string
		data string
		want bool
	}{
		{
			name: "explicit gui entry",
			path: "../../cmd/picocrypt/main_gui.go",
			data: guiOnlySource,
			want: false,
		},
		{
			name: "gui name without build tag stays guarded",
			path: "../../cmd/picocrypt/main_gui.go",
			data: "package main\n",
			want: true,
		},
		{
			name: "cli entry",
			path: "../../cmd/picocrypt/main_cli.go",
			data: "//go:build cli\n\npackage main\n",
			want: true,
		},
		{
			name: "neutral entry",
			path: "../../cmd/picocrypt/main.go",
			data: "package main\n",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldScanPicocryptEntryForCLILocalization(tc.path, []byte(tc.data))
			if got != tc.want {
				t.Fatalf("shouldScanPicocryptEntryForCLILocalization(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func uiProductionGoFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	if err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == "translation" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files = append(files, filepath.ToSlash(path))
		return nil
	}); err != nil {
		t.Fatalf("walk UI production Go files: %v", err)
	}

	sort.Strings(files)
	if len(files) == 0 {
		t.Fatal("found no UI production Go files")
	}
	return files
}

func collectCLILocalizationFailures(t *testing.T) []string {
	t.Helper()

	roots := []string{
		"../cli",
		"../../cmd/picocrypt",
	}
	internalCLIFiles := 0
	scannedMain := false
	scannedMainCLI := false

	var failures []string
	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		isPicocryptCmd := cleanRoot == filepath.Clean("../../cmd/picocrypt")
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}

			if isPicocryptCmd && !shouldScanPicocryptEntryForCLILocalization(path, data) {
				return nil
			}

			if cleanRoot == filepath.Clean("../cli") {
				internalCLIFiles++
			}
			if isPicocryptCmd {
				switch filepath.Base(path) {
				case "main.go":
					scannedMain = true
				case "main_cli.go":
					scannedMainCLI = true
				}
			}

			failures = append(failures, collectForbiddenCLILocalizationTokensFromSource(filepath.ToSlash(path), string(data))...)
			return nil
		}); err != nil {
			t.Fatalf("walk %s for CLI localization guard: %v", root, err)
		}
	}

	if internalCLIFiles == 0 {
		t.Fatal("CLI localization guard did not scan any internal/cli Go files")
	}
	if !scannedMain {
		t.Fatal("CLI localization guard did not scan cmd/picocrypt/main.go")
	}
	if !scannedMainCLI {
		t.Fatal("CLI localization guard did not scan cmd/picocrypt/main_cli.go")
	}
	return failures
}

func collectForbiddenCLILocalizationTokensFromSource(filename, source string) []string {
	var failures []string
	for _, token := range forbiddenCLILocalizationTokens {
		if strings.Contains(source, token) {
			failures = append(failures, fmt.Sprintf("%s: forbidden %q", filename, token))
		}
	}
	return failures
}

func collectForbiddenCLILanguageControlTokensFromSource(filename, source string) []string {
	lowerSource := strings.ToLower(source)
	var failures []string
	for _, token := range forbiddenCLILanguageControlTokens {
		lowerToken := strings.ToLower(token)
		lowerEscapedToken := strings.ToLower(strings.ReplaceAll(token, `"`, `\"`))
		if strings.Contains(lowerSource, lowerToken) || strings.Contains(lowerSource, lowerEscapedToken) {
			failures = append(failures, fmt.Sprintf("%s: forbidden CLI language token %q", filename, token))
		}
	}
	return failures
}

func shouldScanPicocryptEntryForCLILocalization(path string, data []byte) bool {
	// The only cmd/picocrypt allowlist is the GUI bootstrap file, and only when
	// its build tag excludes CLI builds. main.go and main_cli.go stay guarded.
	switch filepath.Base(path) {
	case "main_gui.go", "main_gui_test.go":
		return firstGoBuildExpression(data) != "!cli"
	default:
		return true
	}
}

func firstGoBuildExpression(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "//go:build "):
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "//go:build "))
		case strings.HasPrefix(trimmed, "//"):
			continue
		default:
			return ""
		}
	}
	return ""
}
