package ui

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestLoadTranslations(t *testing.T) {
	setEnglishLocaleForTest(t)
	resetLoadTranslationsForTest(t)

	for i := 0; i < 2; i++ {
		if err := loadTranslations(); err != nil {
			t.Fatalf("loadTranslations call %d returned error: %v", i+1, err)
		}
	}

	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("tr(status.ready) = %q; want Ready", got)
	}

	got := trn("keyfiles.count", "{{.Count}} fallback", 2, map[string]any{"Count": 2})
	if got != "Using 2 keyfiles" {
		t.Fatalf("trn(keyfiles.count, 2) = %q; want Using 2 keyfiles", got)
	}
}

func setEnglishLocaleForTest(t *testing.T) {
	t.Helper()

	t.Setenv("LANGUAGE", "en_US")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "en_US.UTF-8")
}

func resetLoadTranslationsForTest(t *testing.T) {
	t.Helper()

	loadTranslationsOnce = sync.Once{}
	loadTranslationsErr = nil
	t.Cleanup(func() {
		loadTranslationsOnce = sync.Once{}
		loadTranslationsErr = nil
	})
}

func TestLocalizationCatalogJSON(t *testing.T) {
	data, err := translationFS.ReadFile("translation/en.json")
	if err != nil {
		t.Fatalf("read embedded en catalog: %v", err)
	}
	if !utf8.Valid(data) {
		t.Fatal("translation/en.json is not valid UTF-8")
	}

	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse translation/en.json: %v", err)
	}
	if len(catalog) == 0 {
		t.Fatal("translation/en.json is empty")
	}

	for key, value := range catalog {
		if strings.TrimSpace(key) == "" {
			t.Fatal("translation/en.json contains an empty key")
		}
		validateCatalogValue(t, key, value)
	}
}

func TestLocalizationCatalogEmbeddedByLoader(t *testing.T) {
	if _, err := os.Stat("translation/en.json"); err != nil {
		t.Fatalf("translation/en.json missing from package: %v", err)
	}

	source := readPackageSource(t, "localization.go")
	required := []string{
		"//go:embed translation/*.json",
		"lang.AddTranslationsFS(translationFS, \"translation\")",
	}
	for _, want := range required {
		if !strings.Contains(source, want) {
			t.Fatalf("localization.go missing %q", want)
		}
	}
}

func TestFyneUIDisplayStringsUseLocalizationCalls(t *testing.T) {
	files := []string{
		"password_section.go",
		"keyfile_section.go",
		"advanced_section.go",
		"dialogs.go",
		"app.go",
		"drop.go",
		"mobile.go",
		"open_readiness.go",
		"operations.go",
	}

	displayLiterals := map[string]struct{}{
		"Clear": {}, "Copy": {}, "Paste": {}, "Create": {}, "Edit": {},
		"Done": {}, "Change": {}, "Cancel": {}, "Close": {}, "Generate": {},
		"Password": {}, "Confirm password": {}, "Password:": {}, "Confirm password:": {},
		"Non-ASCII password: it is normalized so the volume decrypts on any ": {},
		"Keyfiles:": {}, "Require correct order": {}, "Correct ordering is required": {},
		"Drag and drop your keyfiles here": {}, "Manage keyfiles:": {},
		"Failed to generate keyfile": {}, "Failed to write keyfile": {},
		"Paranoid mode": {}, "Compress files": {}, "Reed-Solomon": {}, "Delete files": {},
		"Deniability": {}, "Recursively": {}, "Split:": {}, "Force decrypt": {},
		"Verify first": {}, "Delete volume": {}, "Delete encrypted": {}, "Auto unzip": {},
		"Same level": {}, "Size": {}, "Advanced:": {},
		"Adds Serpent-CTR and stronger KDF/MAC settings for defense in depth":        {},
		"Compress files with Deflate before encrypting":                              {},
		"Add redundancy to repair limited file corruption":                           {},
		"Delete the input files after encryption":                                    {},
		"Warning: only use this if you know what it does!":                           {},
		"Split the output file into smaller chunks":                                  {},
		"Choose the chunk units":                                                     {},
		"Keep unverified output when integrity checks fail; output may be corrupted": {},
		"Verify integrity before decryption (slower but more secure)":                {},
		"Delete the volume after a successful decryption":                            {},
		"Extract .zip upon decryption (may overwrite files)":                         {},
		"Extract .zip contents to same folder as volume":                             {},
		"Comments (not encrypted)":                                                   {}, "Save output as:": {}, "Process": {},
		"(multiple values)": {}, " (ensure >": {},
		"Failed to access startup path": {}, "Some startup paths could not be accessed": {},
		"Failed to walk through dropped items": {}, "Scanning files... (%s)": {},
		"Failed to stat dropped item": {}, "1 folder": {}, "Zip and Encrypt": {},
		"1 file": {}, "Encrypt": {}, "Volume for decryption": {}, "Decrypt": {},
		"Failed to derive split volume path": {}, "Read access denied": {},
		"Cannot read header, volume may be deniable": {}, "The volume header is damaged": {},
		"Failed to stat dropped items": {}, "%d files": {}, "%d folders": {},
		"1 file and %d folders": {}, "%d files and 1 folder": {},
		"1 file and 1 folder": {}, "%d files and %d folders": {},
		"Keyfile read access denied": {}, "Preparing iCloud files": {},
		"Some iCloud files are not downloaded": {},
		"Progress:":                            {}, "Operation cancelled by user": {}, "Picocrypt-NG on GitHub": {},
		"About:": {}, "Length: %d": {}, "Uppercase": {}, "Lowercase": {},
		"Numbers": {}, "Symbols": {}, "Copy to clipboard": {},
		"Generate password:": {}, "Warning:": {}, "Output already exists. Overwrite?": {},
		"Select Files": {}, "Select Folder": {}, "App Storage (large files)": {},
		"Tip: For large files, copy them to App Storage first": {},
		"Failed to create app storage":                         {}, "Failed to read app storage": {},
		"App Storage is empty.\n\n": {}, "Copy Path": {}, "Path copied to clipboard": {},
		"App Storage": {}, "No files in app storage": {}, "Select from App Storage": {},
		"Failed to access file: ":                                 {},
		"Folder selection is not fully supported on Android.\n\n": {},
		"Copy Path to Clipboard":                                  {}, "Open App Storage": {}, "Folder Selection": {},
		"No files to process": {}, "Completed (%d files)": {}, "Failed (all %d files)": {},
		"Completed (%d ok, %d failed)": {}, "Processing file %d/%d...": {},
		"Invalid split size": {}, "Completed": {},
		"Completed (some files couldn't be deleted)":                             {},
		"Integrity check failed; kept output is unverified and may be corrupted": {},
		"Completed (volume couldn't be deleted)":                                 {},
	}

	var failures []string
	for _, file := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		var stack []ast.Node
		ast.Inspect(parsed, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)

			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value := strings.Trim(lit.Value, "`\"")
			if _, ok := displayLiterals[value]; !ok {
				return true
			}
			if stringLiteralInsideTranslationCall(stack) {
				return true
			}
			failures = append(failures, fset.Position(lit.Pos()).String()+": "+value)
			return true
		})
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("display strings must be passed through tr/trn:\n%s", strings.Join(failures, "\n"))
	}
}

func TestFyneUITranslationCallKeysExistInCatalog(t *testing.T) {
	data, err := translationFS.ReadFile("translation/en.json")
	if err != nil {
		t.Fatalf("read embedded en catalog: %v", err)
	}
	var catalog map[string]any
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("parse translation/en.json: %v", err)
	}

	files := []string{
		"password_section.go",
		"keyfile_section.go",
		"advanced_section.go",
		"dialogs.go",
		"app.go",
		"drop.go",
		"mobile.go",
		"open_readiness.go",
		"operations.go",
	}

	var missing []string
	for _, file := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isTranslationCall(call) || len(call.Args) == 0 {
				return true
			}
			keyLit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || keyLit.Kind != token.STRING {
				return true
			}
			key := strings.Trim(keyLit.Value, "`\"")
			value, ok := catalog[key]
			if !ok {
				missing = append(missing, fset.Position(keyLit.Pos()).String()+": "+key)
				return true
			}
			if translationCallName(call) == "trn" {
				if _, ok := value.(map[string]any); !ok {
					missing = append(missing, fset.Position(keyLit.Pos()).String()+": "+key+" is not plural")
				}
			}
			return true
		})
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("translation calls without matching catalog entries:\n%s", strings.Join(missing, "\n"))
	}
}

func TestLocalizationLoadedByNewAppBeforeReturn(t *testing.T) {
	source := readPackageSource(t, "app.go")
	stateIndex := strings.Index(source, "app.NewState()")
	loadIndex := strings.Index(source, "loadTranslations()")
	returnIndex := strings.Index(source, "return &App{")
	if stateIndex < 0 || loadIndex < 0 || returnIndex < 0 {
		t.Fatalf("app.go missing NewApp localization sequence: state=%d load=%d return=%d", stateIndex, loadIndex, returnIndex)
	}
	if !(stateIndex < loadIndex && loadIndex < returnIndex) {
		t.Fatalf("loadTranslations order is wrong: state=%d load=%d return=%d", stateIndex, loadIndex, returnIndex)
	}
}

func validateCatalogValue(t *testing.T, key string, value any) {
	t.Helper()

	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			t.Fatalf("translation %q has an empty value", key)
		}
	case map[string]any:
		if _, ok := v["other"]; !ok {
			t.Fatalf("plural translation %q is missing other", key)
		}
		for form, raw := range v {
			if strings.TrimSpace(form) == "" {
				t.Fatalf("plural translation %q contains an empty plural form", key)
			}
			text, ok := raw.(string)
			if !ok {
				t.Fatalf("plural translation %q form %q has non-string value %T", key, form, raw)
			}
			if strings.TrimSpace(text) == "" {
				t.Fatalf("plural translation %q form %q has an empty value", key, form)
			}
			if !strings.Contains(text, "{{.Count}}") {
				t.Fatalf("plural translation %q form %q omits {{.Count}}", key, form)
			}
		}
	default:
		t.Fatalf("translation %q has unsupported value type %T", key, value)
	}
}

func readPackageSource(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func stringLiteralInsideTranslationCall(stack []ast.Node) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		call, ok := stack[i].(*ast.CallExpr)
		if ok && isTranslationCall(call) {
			return true
		}
	}
	return false
}

func isTranslationCall(call *ast.CallExpr) bool {
	return translationCallName(call) != ""
}

func translationCallName(call *ast.CallExpr) string {
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name == "tr" || ident.Name == "trn" {
			return ident.Name
		}
	}
	return ""
}
