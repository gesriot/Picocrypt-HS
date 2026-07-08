package ui

import (
	"testing"
	"testing/fstest"

	"Picocrypt-NG/internal/app"

	"fyne.io/fyne/v2"
)

func TestLanguageSelectorClosedTextUsesLanguageCode(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/de.json": {Data: []byte(`{"status.ready":"Bereit"}`)},
	}
	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}
	if err := setActiveLanguage("de"); err != nil {
		t.Fatalf("setActiveLanguage(de) returned error: %v", err)
	}

	a := &App{}
	selector := newLanguageSelector(a)
	if selector.button.Text != "de" {
		t.Fatalf("selector closed text = %q; want de", selector.button.Text)
	}
}

func TestLanguageSelectorMenuUsesNativeNamesAndNoIcons(t *testing.T) {
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/fr.json": {Data: []byte(`{"status.ready":"Pret"}`)},
		"translation/it.json": {Data: []byte(`{"status.ready":"Pronto"}`)},
	}
	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	a := &App{}
	selector := newLanguageSelector(a)
	menu := selector.menu()
	got := make([]string, 0, len(menu.Items))
	for _, item := range menu.Items {
		got = append(got, item.Label)
		if item.Icon != nil {
			t.Fatalf("language menu item %q has an icon; flags/icons are not allowed", item.Label)
		}
	}
	want := []string{"English", "Français", "Italiano"}
	if len(got) != len(want) {
		t.Fatalf("menu labels = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("menu label %d = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestLanguagePreferenceRoundTrip(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	fyneApp.Preferences().SetString(languagePreferenceKey, "fr")

	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"status.ready":"Ready"}`)},
		"translation/fr.json": {Data: []byte(`{"status.ready":"Pret"}`)},
	}
	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	a := &App{fyneApp: fyneApp}
	if err := a.loadPreferredLanguage(fyneApp.Preferences()); err != nil {
		t.Fatalf("loadPreferredLanguage returned error: %v", err)
	}
	if got := activeLanguage(); got != "fr" {
		t.Fatalf("activeLanguage after preference load = %q; want fr", got)
	}
	if err := a.SwitchLanguage("en"); err != nil {
		t.Fatalf("SwitchLanguage(en) returned error: %v", err)
	}
	if got := fyneApp.Preferences().StringWithFallback(languagePreferenceKey, ""); got != "en" {
		t.Fatalf("stored language preference = %q; want en", got)
	}
}

func TestLanguageSelectionRelocalizesBuiltDesktopControls(t *testing.T) {
	if raceEnabled {
		t.Skip("Fyne v2.7.4 internal cache races under -race; covered on non-race matrices")
	}
	resetLocalizationForTest(t)
	testFS := fstest.MapFS{
		"translation/en.json": {Data: []byte(`{"action.clear":"Clear","drop.prompt":"Drop","status.ready":"Ready","action.start":"Start"}`)},
		"translation/zz.json": {Data: []byte(`{"action.clear":"ZZ Clear","drop.prompt":"ZZ Drop","status.ready":"ZZ Ready","action.start":"ZZ Start"}`)},
	}
	if err := loadTranslationsFromFS(testFS, "translation"); err != nil {
		t.Fatalf("loadTranslationsFromFS returned error: %v", err)
	}

	fyneApp := newTestFyneApp(t)
	state, err := app.NewState()
	if err != nil {
		t.Fatalf("NewState returned error: %v", err)
	}
	a := &App{State: state, fyneApp: fyneApp, DPI: 1.0}
	var content fyne.CanvasObject
	fyne.DoAndWait(func() {
		a.Window = fyneApp.NewWindow("language-test")
		content = a.buildUI()
		a.Window.SetContent(content)
	})

	if a.clearButton.Text != "Clear" {
		t.Fatalf("initial clearButton.Text = %q; want Clear", a.clearButton.Text)
	}
	if err := a.SwitchLanguage("zz"); err != nil {
		t.Fatalf("SwitchLanguage(zz) returned error: %v", err)
	}
	fyne.DoAndWait(func() {})
	if a.clearButton.Text != "ZZ Clear" {
		t.Fatalf("clearButton.Text after language switch = %q; want ZZ Clear", a.clearButton.Text)
	}
	if a.inputLabel.Text != "ZZ Drop" {
		t.Fatalf("inputLabel.Text after language switch = %q; want ZZ Drop", a.inputLabel.Text)
	}
	if a.startButton.Text != "ZZ Start" {
		t.Fatalf("startButton.Text after language switch = %q; want ZZ Start", a.startButton.Text)
	}
}
