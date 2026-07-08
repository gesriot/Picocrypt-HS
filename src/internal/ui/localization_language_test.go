package ui

import (
	"testing"
	"testing/fstest"
)

func TestProjectLocalTranslatorSwitchesActiveLanguage(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready","selection.files":{"one":"{{.Count}} file","other":"{{.Count}} files"}}`),
		},
		"translation/zz.json": {
			Data: []byte(`{"status.ready":"ZZ Ready","selection.files":{"one":"{{.Count}} zz-file","other":"{{.Count}} zz-files"}}`),
		},
	}

	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if got := tr("status.ready", "fallback"); got != "Ready" {
		t.Fatalf("default tr(status.ready) = %q; want Ready", got)
	}
	if err := setActiveLanguage("zz"); err != nil {
		t.Fatalf("setActiveLanguage(zz) returned error: %v", err)
	}
	if got := tr("status.ready", "fallback"); got != "ZZ Ready" {
		t.Fatalf("tr(status.ready) after language switch = %q; want ZZ Ready", got)
	}
	if got := trn("selection.files", "{{.Count}} files", 2, map[string]any{"Count": 2}); got != "2 zz-files" {
		t.Fatalf("trn(selection.files, 2) = %q; want 2 zz-files", got)
	}
}

func TestProjectLocalTranslatorRejectsUnavailableLanguage(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready"}`),
		},
	}

	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if err := setActiveLanguage("ru"); err == nil {
		t.Fatal("setActiveLanguage(ru) returned nil; want unavailable-language error")
	}
	if got := activeLanguage(); got != "en" {
		t.Fatalf("activeLanguage after rejected switch = %q; want en", got)
	}
}

func TestBundledLanguageOptionsOnlyIncludesLoadedCatalogs(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {
			Data: []byte(`{"status.ready":"Ready"}`),
		},
		"translation/fr.json": {
			Data: []byte(`{"status.ready":"Pret"}`),
		},
	}

	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	got := bundledLanguageOptions()
	want := []LanguageOption{
		{Code: "en", Name: "English"},
		{Code: "fr", Name: "Français"},
	}
	if len(got) != len(want) {
		t.Fatalf("bundledLanguageOptions length = %d; want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bundledLanguageOptions[%d] = %#v; want %#v", i, got[i], want[i])
		}
	}
}

func resetLocalizationForTest(t *testing.T) {
	t.Helper()
	original := localizationState
	localizationState = newLocalizationState()
	t.Cleanup(func() {
		localizationState = original
	})
}
