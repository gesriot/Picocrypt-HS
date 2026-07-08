package ui

type LanguageCode string

type LanguageOption struct {
	Code LanguageCode
	Name string
}

const languagePreferenceKey = "ui.language"

var knownLanguageOptions = []LanguageOption{
	{Code: "en", Name: "English"},
	{Code: "ru", Name: "Русский"},
	{Code: "de", Name: "Deutsch"},
	{Code: "fr", Name: "Français"},
	{Code: "it", Name: "Italiano"},
	{Code: "es", Name: "Español"},
}

func bundledLanguageOptions() []LanguageOption {
	loaded := localizationState.loadedCodes()
	options := make([]LanguageOption, 0, len(knownLanguageOptions))
	for _, opt := range knownLanguageOptions {
		if loaded[opt.Code] {
			options = append(options, opt)
		}
	}
	return options
}
