// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"Picocrypt-NG/internal/log"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// showProgressModal shows the progress dialog.
func (a *App) showProgressModal(session *operationSession) {
	// Reset bindings for new operation
	if err := a.boundProgress.Set(0); err != nil {
		log.Error("reset operation progress binding", log.Err(err))
	}
	if err := a.boundStatus.Set(""); err != nil {
		log.Error("reset operation status binding", log.Err(err))
	}

	// Create bound widgets - they auto-update when bindings change
	a.progressBar = widget.NewProgressBarWithData(a.boundProgress)
	a.progressBar.Min = 0
	a.progressBar.Max = 1

	// Status shows speed and ETA (e.g., "Encrypting at 10.33 MiB/s (ETA: 00:00:00)")
	// Progress bar already shows percentage, so no need for separate percentage label
	a.progressStatus = widget.NewLabelWithData(a.boundStatus)

	a.cancelButton = widget.NewButton(tr("action.cancel", "Cancel"), func() {
		a.cancelOperation(session)
	})

	progressContent := container.NewVBox(
		container.NewBorder(nil, nil, nil, a.cancelButton, a.progressBar),
		a.progressStatus,
	)

	a.progressModal = dialog.NewCustomWithoutButtons(tr("dialog.progress.title", "Progress:"), progressContent, a.Window)
	a.progressModal.Show()
}

// showAboutModal shows the About dialog. It is the GUI's only version
// indicator: the window title intentionally carries none (#133).
func (a *App) showAboutModal() {
	a.aboutVersionLabel = widget.NewLabelWithStyle(
		tr("dialog.about.version_label", "Picocrypt HS {{.Version}}", map[string]any{
			"Version": a.Version,
		}), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	repo := widget.NewHyperlink(tr("dialog.about.github_link", "Picocrypt-HS on GitHub"), &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/gesriot/Picocrypt-HS",
	})

	content := container.NewVBox(
		a.aboutVersionLabel,
		container.NewCenter(repo),
	)

	a.aboutModal = dialog.NewCustom(tr("dialog.about.title", "About:"), tr("action.close", "Close"), content, a.Window)
	a.aboutModal.Show()
}

func passgenLengthText(length int) string {
	return tr("dialog.passgen.length", "Length: {{.Length}}", map[string]any{
		"Length": length,
	})
}

// showPassgenModal shows the password generator dialog.
func (a *App) showPassgenModal() {
	lengthLabel := widget.NewLabel(passgenLengthText(int(a.State.PassgenLength)))

	lengthSlider := widget.NewSlider(12, 64)
	lengthSlider.Value = float64(a.State.PassgenLength)
	lengthSlider.Step = 1
	lengthSlider.OnChanged = func(value float64) {
		a.State.PassgenLength = int32(value)
		lengthLabel.SetText(passgenLengthText(int(value)))
	}

	upperCheck := widget.NewCheck(tr("dialog.passgen.uppercase", "Uppercase"), func(checked bool) {
		a.State.PassgenUpper = checked
	})
	upperCheck.SetChecked(a.State.PassgenUpper)

	lowerCheck := widget.NewCheck(tr("dialog.passgen.lowercase", "Lowercase"), func(checked bool) {
		a.State.PassgenLower = checked
	})
	lowerCheck.SetChecked(a.State.PassgenLower)

	numsCheck := widget.NewCheck(tr("dialog.passgen.numbers", "Numbers"), func(checked bool) {
		a.State.PassgenNums = checked
	})
	numsCheck.SetChecked(a.State.PassgenNums)

	symbolsCheck := widget.NewCheck(tr("dialog.passgen.symbols", "Symbols"), func(checked bool) {
		a.State.PassgenSymbols = checked
	})
	symbolsCheck.SetChecked(a.State.PassgenSymbols)

	copyCheck := widget.NewCheck(tr("dialog.passgen.copy", "Copy to clipboard"), func(checked bool) {
		a.State.PassgenCopy = checked
	})
	copyCheck.SetChecked(a.State.PassgenCopy)

	content := container.NewVBox(
		lengthLabel,
		lengthSlider,
		upperCheck,
		lowerCheck,
		numsCheck,
		symbolsCheck,
		copyCheck,
	)

	a.passgenModal = dialog.NewCustomConfirm(tr("dialog.passgen.title", "Generate password:"), tr("action.generate", "Generate"), tr("action.cancel", "Cancel"), content, func(generate bool) {
		if generate {
			// Check if at least one character type is selected
			if !a.State.PassgenUpper && !a.State.PassgenLower && !a.State.PassgenNums && !a.State.PassgenSymbols {
				return
			}
			password := a.State.GenPassword()
			a.State.Password = password
			a.State.CPassword = password
			if a.passwordEntry != nil {
				a.passwordEntry.SetText(password)
			}
			if a.cPasswordEntry != nil {
				a.cPasswordEntry.SetText(password)
			}
			a.updatePasswordStrength()
			a.updateValidation()
		}
		a.State.ShowPassgen = false
	}, a.Window)
	a.State.ShowPassgen = true
	a.State.ModalID++
	a.passgenModal.Show()
}

// showOverwriteModal shows the overwrite confirmation dialog.
func (a *App) showOverwriteModal() {
	a.overwriteModal = dialog.NewConfirm(tr("dialog.overwrite.title", "Warning:"), tr("dialog.overwrite.message", "Output already exists. Overwrite?"), func(overwrite bool) {
		a.State.ShowOverwrite = false
		if overwrite {
			a.startWork()
		}
	}, a.Window)
	a.State.ShowOverwrite = true
	a.State.ModalID++
	a.overwriteModal.Show()
}

func normalizeSelectedOutputPath(filePath, mode, inputFile string, multiInput, compress bool) string {
	base := filepath.Base(filePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	file := filepath.Join(filepath.Dir(filePath), base)

	if mode == "encrypt" {
		if multiInput || compress {
			return file + ".zip.pcv"
		}
		return file + filepath.Ext(inputFile) + ".pcv"
	}

	if strings.HasSuffix(inputFile, ".zip.pcv") {
		return file + ".zip"
	}
	tmp := strings.TrimSuffix(filepath.Base(inputFile), ".pcv")
	return file + filepath.Ext(tmp)
}

// changeOutputFile opens a dialog to change the output file path.
func (a *App) changeOutputFile() {
	saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}

		filePath := writer.URI().Path()
		_ = writer.Close()
		a.State.OutputFile = normalizeSelectedOutputPath(
			filePath,
			a.State.Mode,
			a.State.InputFile,
			len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0,
			a.State.Compress,
		)
		a.State.OutputChosenViaSaveDialog = true
		a.State.SetReadyStatus()
		a.updateUIState()
	}, a.Window)

	// Prefill filename - preserve user's choice, only generate random name if needed
	tmp := strings.TrimSuffix(filepath.Base(a.State.OutputFile), ".pcv")
	defaultName := strings.TrimSuffix(tmp, filepath.Ext(tmp))
	// Only generate a new random name if there isn't already a meaningful filename,
	// or if the current name is auto-generated (starts with "encrypted-")
	if a.State.Mode == "encrypt" && (len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 || a.State.Compress) {
		if defaultName == "" || strings.HasPrefix(defaultName, "encrypted-") {
			defaultName = "encrypted-" + strconv.Itoa(int(time.Now().Unix()))
		}
	}
	saveDialog.SetFileName(defaultName)

	// Set start directory
	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		uri := storage.NewFileURI(startDir)
		if listable, err := storage.ListerForURI(uri); err == nil {
			saveDialog.SetLocation(listable)
		}
	}

	a.showFileDialogWithResize(saveDialog, fyne.NewSize(600, 450))
}
