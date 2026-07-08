package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed translation/*.json
var translationFS embed.FS

var localizationState = newLocalizationState()

type localizationRuntime struct {
	mu      sync.RWMutex
	once    sync.Once
	loadErr error

	bundle    *i18n.Bundle
	localizer *i18n.Localizer
	active    LanguageCode
	loaded    map[LanguageCode]bool
	tags      map[LanguageCode]string
}

func newLocalizationState() *localizationRuntime {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	return &localizationRuntime{
		bundle:    bundle,
		localizer: i18n.NewLocalizer(bundle, "en"),
		active:    "en",
		loaded:    map[LanguageCode]bool{},
		tags:      map[LanguageCode]string{},
	}
}

func loadTranslations() error {
	localizationState.once.Do(func() {
		localizationState.loadErr = loadTranslationsFromFS(translationFS, "translation")
	})
	return localizationState.loadErr
}

func loadTranslationsFromFS(files fs.FS, dir string) error {
	entries, err := fs.ReadDir(files, dir)
	if err != nil {
		return err
	}

	localizationState.mu.Lock()
	defer localizationState.mu.Unlock()

	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, entry.Name()))
		data, readErr := fs.ReadFile(files, path)
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			continue
		}
		messageFile, parseErr := localizationState.bundle.ParseMessageFileBytes(data, entry.Name())
		if parseErr != nil {
			if firstErr == nil {
				firstErr = parseErr
			}
			continue
		}
		code := LanguageCode(strings.TrimSuffix(entry.Name(), ".json"))
		localizationState.loaded[code] = true
		localizationState.tags[code] = messageFile.Tag.String()
	}
	if !localizationState.loaded["en"] {
		return fmt.Errorf("translation/en.json is required")
	}
	localizationState.active = "en"
	localizationState.localizer = i18n.NewLocalizer(localizationState.bundle, "en")
	return firstErr
}

func setActiveLanguage(code LanguageCode) error {
	localizationState.mu.Lock()
	defer localizationState.mu.Unlock()

	if code == "" {
		code = "en"
	}
	if !localizationState.loaded[code] {
		return fmt.Errorf("language %q is not bundled", code)
	}
	localizationState.active = code
	tag := localizationState.tags[code]
	if tag == "" {
		tag = string(code)
	}
	localizationState.localizer = i18n.NewLocalizer(localizationState.bundle, tag, "en")
	return nil
}

func activeLanguage() LanguageCode {
	localizationState.mu.RLock()
	defer localizationState.mu.RUnlock()
	return localizationState.active
}

func (l *localizationRuntime) loadedCodes() map[LanguageCode]bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make(map[LanguageCode]bool, len(l.loaded))
	for code, loaded := range l.loaded {
		out[code] = loaded
	}
	return out
}

func tr(key, fallback string, data ...any) string {
	return localize(key, fallback, 0, false, data...)
}

func trn(key, fallback string, count int, data ...any) string {
	return localize(key, fallback, count, true, data...)
}

func localize(key, fallback string, count int, plural bool, data ...any) string {
	localizationState.mu.RLock()
	localizer := localizationState.localizer
	localizationState.mu.RUnlock()

	var d0 any
	if len(data) > 0 {
		d0 = data[0]
	}
	config := &i18n.LocalizeConfig{
		MessageID: key,
		DefaultMessage: &i18n.Message{
			ID:    key,
			Other: fallback,
		},
		TemplateData: d0,
	}
	if plural {
		config.PluralCount = count
	}
	text, err := localizer.Localize(config)
	if err != nil {
		return fallbackWithData(key, fallback, d0)
	}
	return text
}

func fallbackWithData(key, fallback string, data any) string {
	t, err := template.New(key).Parse(fallback)
	if err != nil {
		return fallback
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return fallback
	}
	return b.String()
}
