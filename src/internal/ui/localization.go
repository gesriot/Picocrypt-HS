package ui

import (
	"embed"
	"sync"

	"fyne.io/fyne/v2/lang"
)

//go:embed translation/*.json
var translationFS embed.FS

var (
	loadTranslationsOnce sync.Once
	loadTranslationsErr  error
)

func loadTranslations() error {
	loadTranslationsOnce.Do(func() {
		loadTranslationsErr = lang.AddTranslationsFS(translationFS, "translation")
	})
	return loadTranslationsErr
}

func tr(key, fallback string, data ...any) string {
	return lang.X(key, fallback, data...)
}

func trn(key, fallback string, count int, data ...any) string {
	return lang.XN(key, fallback, count, data...)
}
