package ui

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLoadTranslations(t *testing.T) {
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
