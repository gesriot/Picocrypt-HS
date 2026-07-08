// Package ui provides mobile-specific UI components for Picocrypt NG.
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

// isMobile returns true if running on a mobile device
func isMobile() bool {
	return fyne.CurrentDevice().IsMobile()
}

// buildMobileUI creates the mobile-optimized UI layout
func (a *App) buildMobileUI() fyne.CanvasObject {
	// File selection section (replaces drag-drop)
	fileSection := a.buildMobileFileSection()

	// Password section with larger buttons
	passwordSection := a.buildMobilePasswordSection()

	// Keyfiles section
	keyfilesSection := a.buildMobileKeyfilesSection()

	// Comments section
	commentsSection := a.buildMobileCommentsSection()

	// Advanced section
	a.advancedContainer = container.NewVBox()
	a.updateMobileAdvancedSection()

	// Output section
	outputSection := a.buildMobileOutputSection()

	// Start button - large and prominent
	a.startButton = widget.NewButton(a.State.StartLabel, a.onClickStart)
	a.startButton.Importance = widget.HighImportance

	a.statusLabel = NewColoredLabel(a.State.MainStatus, a.State.MainStatusColor)

	// Main content in a vertical box
	a.mainContent = container.NewVBox(
		fileSection,
		widget.NewSeparator(),
		passwordSection,
		keyfilesSection,
		widget.NewSeparator(),
		commentsSection,
		widget.NewLabel("Advanced:"),
		a.advancedContainer,
		outputSection,
		widget.NewSeparator(),
		a.startButton,
		a.statusLabel,
	)

	// Wrap in scroll container for small screens
	scroll := container.NewVScroll(container.NewPadded(a.mainContent))

	a.updateUIState()

	return scroll
}

// buildMobileFileSection creates the file selection section for mobile
func (a *App) buildMobileFileSection() fyne.CanvasObject {
	a.inputLabel = widget.NewLabel(a.State.InputLabel)
	a.inputLabel.Wrapping = fyne.TextWrapWord

	// Select Files button - opens file picker
	selectFilesBtn := widget.NewButtonWithIcon("Select Files", theme.FolderOpenIcon(), func() {
		a.showMobileFilePicker()
	})
	selectFilesBtn.Importance = widget.HighImportance

	// Select Folder button
	selectFolderBtn := widget.NewButtonWithIcon("Select Folder", theme.FolderIcon(), func() {
		a.showMobileFolderPicker()
	})

	// Clear button
	a.clearButton = widget.NewButton("Clear", a.resetUI)
	a.clearButton.Importance = widget.MediumImportance

	// Button row
	buttonRow := container.NewGridWithColumns(3, selectFilesBtn, selectFolderBtn, a.clearButton)

	// App Storage button for large files (no copying required)
	appStorageBtn := widget.NewButton("App Storage (large files)", func() {
		a.showAppStorageDialog()
	})

	// Help text
	helpText := widget.NewLabel("Tip: For large files, copy them to App Storage first")
	helpText.Wrapping = fyne.TextWrapWord
	helpText.TextStyle = fyne.TextStyle{Italic: true}

	return container.NewVBox(
		a.inputLabel,
		buttonRow,
		appStorageBtn,
		helpText,
	)
}

// getAppStorageDir returns the app's local storage directory path.
// Files in this directory can be accessed directly without copying.
func (a *App) getAppStorageDir() string {
	filesDir := os.Getenv("FILESDIR")
	if filesDir != "" {
		return filepath.Join(filesDir, "Documents")
	}
	// Fallback for non-Android or testing
	return filepath.Join(os.TempDir(), "picocrypt-documents")
}

// showAppStorageDialog shows a dialog explaining how to use app storage for large files
func (a *App) showAppStorageDialog() {
	appDir := a.getAppStorageDir()

	// Ensure directory exists
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		a.State.SetStatus("Failed to create app storage", util.RED)
		a.refreshUI()
		return
	}

	// List files in app storage
	files, err := os.ReadDir(appDir)
	if err != nil {
		a.State.SetStatus("Failed to read app storage", util.RED)
		a.refreshUI()
		return
	}

	if len(files) == 0 {
		// Show instructions
		content := widget.NewLabel(
			"App Storage is empty.\n\n" +
				"To use large files without copying:\n" +
				"1. Open a file manager app\n" +
				"2. Copy files to:\n" +
				"   " + appDir + "\n" +
				"3. Come back and select them here")
		content.Wrapping = fyne.TextWrapWord

		copyPathBtn := widget.NewButton("Copy Path", func() {
			a.fyneApp.Clipboard().SetContent(appDir)
			a.State.SetStatus("Path copied to clipboard", util.WHITE)
			a.refreshUI()
		})

		d := dialog.NewCustom("App Storage", "Close", container.NewVBox(content, copyPathBtn), a.Window)
		d.Show()
		return
	}

	// Show file list
	var items []string
	for _, f := range files {
		if !f.IsDir() {
			items = append(items, f.Name())
		}
	}

	if len(items) == 0 {
		a.State.SetStatus("No files in app storage", util.YELLOW)
		a.refreshUI()
		return
	}

	list := widget.NewList(
		func() int { return len(items) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(items[i])
		},
	)
	list.OnSelected = func(id widget.ListItemID) {
		selectedPath := filepath.Join(appDir, items[id])
		a.onDrop([]string{selectedPath})
	}

	d := dialog.NewCustom("Select from App Storage", "Cancel", list, a.Window)
	d.Resize(fyne.NewSize(300, 400))
	d.Show()
}

// showMobileFilePicker opens the native file picker for mobile
func (a *App) showMobileFilePicker() {
	fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer func() { _ = reader.Close() }()

		// On Android, content:// URIs don't work with os.Stat()
		// We need to copy the file to a local temp directory
		uri := reader.URI()
		if uri.Scheme() == "content" {
			localPath, copyErr := a.copyURIToTemp(reader, uri.Name())
			if copyErr != nil {
				a.State.SetStatus("Failed to access file: "+copyErr.Error(), util.RED)
				a.refreshUI()
				return
			}
			a.onDrop([]string{localPath})
		} else {
			// For file:// URIs, use the path directly
			a.onDrop([]string{uri.Path()})
		}
	}, a.Window)

	fd.Show()
}

// showMobileFolderPicker opens the native folder picker for mobile
func (a *App) showMobileFolderPicker() {
	// On Android, folder picking via SAF has issues with recursive listing
	// Direct users to use App Storage instead
	a.showFolderNotSupportedDialog()
}

// showFolderNotSupportedDialog shows a dialog explaining folder limitations on Android
func (a *App) showFolderNotSupportedDialog() {
	appDir := a.getAppStorageDir()

	content := widget.NewLabel(
		"Folder selection is not fully supported on Android.\n\n" +
			"For folders, please:\n" +
			"1. Copy your folder to App Storage using a file manager\n" +
			"2. Use 'App Storage (large files)' button to select it\n\n" +
			"App Storage path:\n" + appDir)
	content.Wrapping = fyne.TextWrapWord

	copyPathBtn := widget.NewButton("Copy Path to Clipboard", func() {
		a.fyneApp.Clipboard().SetContent(appDir)
		a.State.SetStatus("Path copied to clipboard", util.WHITE)
		a.refreshUI()
	})

	openAppStorageBtn := widget.NewButton("Open App Storage", func() {
		a.showAppStorageDialog()
	})

	buttons := container.NewHBox(copyPathBtn, openAppStorageBtn)

	d := dialog.NewCustom("Folder Selection", "Close", container.NewVBox(content, buttons), a.Window)
	d.Show()
}

// getMobileTempDir returns the temp directory for mobile file copies.
// Uses app's internal storage which is more reliable on Android.
func (a *App) getMobileTempDir() string {
	// Use FILESDIR env var if available (set by Android native code)
	filesDir := os.Getenv("FILESDIR")
	if filesDir != "" {
		return filepath.Join(filesDir, "picocrypt-temp")
	}
	// Fallback to system temp
	return filepath.Join(os.TempDir(), "picocrypt-mobile")
}

// CleanupMobileTempFiles removes all temporary files created for mobile operations.
// Call this after encryption/decryption is complete.
func (a *App) CleanupMobileTempFiles() {
	tempDir := a.getMobileTempDir()
	_ = os.RemoveAll(tempDir)
}

func validateMobileTempFilename(name string) error {
	if name == "" {
		return errors.New("unsafe file name")
	}
	if name == "." || name == ".." {
		return errors.New("unsafe file name")
	}
	if strings.ContainsAny(name, `/\`) {
		return errors.New("unsafe file name")
	}
	if filepath.IsAbs(name) {
		return errors.New("unsafe file name")
	}
	if len(name) >= 2 && name[1] == ':' {
		return errors.New("unsafe file name")
	}
	if filepath.Base(name) != name {
		return errors.New("unsafe file name")
	}

	trimmed := strings.TrimRight(name, " .")
	if trimmed == "" || trimmed != name || trimmed == "." || trimmed == ".." {
		return errors.New("unsafe file name")
	}

	return nil
}

// copyURIToTemp copies a file from a content:// URI to a local temp file
// Returns the path to the local file
func (a *App) copyURIToTemp(reader io.Reader, filename string) (string, error) {
	if err := validateMobileTempFilename(filename); err != nil {
		return "", err
	}

	// Create temp directory for mobile file copies
	tempDir := a.getMobileTempDir()
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return "", err
	}

	// Create the destination file
	destPath := filepath.Join(tempDir, filename)
	destFile, err := fileops.CreateSecureNoSymlink(destPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = destFile.Close() }()

	// Copy the content
	_, err = io.Copy(destFile, reader)
	if err != nil {
		_ = os.Remove(destPath)
		return "", err
	}

	return destPath, nil
}

// buildMobilePasswordSection creates the password section for mobile with larger buttons
func (a *App) buildMobilePasswordSection() fyne.CanvasObject {
	// Password buttons - 3 per row for better touch targets
	a.showHideBtn = widget.NewButton(passwordVisibilityLabel(a.State.PasswordMode), func() {
		a.State.TogglePasswordVisibility()
		snap := a.State.UISnapshot()
		a.showHideBtn.SetText(passwordVisibilityLabel(snap.PasswordMode))
		hidden := snap.PasswordMode == app.PasswordModeHidden
		a.passwordEntry.SetHidden(hidden)
		a.cPasswordEntry.SetHidden(hidden)
	})

	a.clearPwdBtn = widget.NewButton("Clear", func() {
		a.State.Password = ""
		a.State.CPassword = ""
		a.passwordEntry.SetText("")
		a.cPasswordEntry.SetText("")
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	})

	a.copyBtn = widget.NewButton("Copy", func() {
		a.fyneApp.Clipboard().SetContent(a.State.Password)
	})

	a.pasteBtn = widget.NewButton("Paste", func() {
		text := a.fyneApp.Clipboard().Content()
		a.State.Password = text
		a.passwordEntry.SetText(text)
		if a.State.Mode != "decrypt" {
			a.State.CPassword = text
			a.cPasswordEntry.SetText(text)
		}
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	})

	a.createBtn = widget.NewButton("Create", func() {
		a.showPassgenModal()
	})

	// Two rows of buttons for better touch targets
	buttonRow1 := container.NewGridWithColumns(3, a.showHideBtn, a.clearPwdBtn, a.copyBtn)
	buttonRow2 := container.NewGridWithColumns(2, a.pasteBtn, a.createBtn)

	// Password input
	a.passwordEntry = NewPasswordEntry()
	a.passwordEntry.SetPlaceHolder("Password")
	a.passwordEntry.OnChanged = func(text string) {
		a.State.Password = text
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState()
	}

	a.strengthIndicator = NewPasswordStrengthIndicator()
	passwordRow := container.NewBorder(nil, nil, nil, a.strengthIndicator, a.passwordEntry)

	// Confirm password
	a.cPasswordEntry = NewPasswordEntry()
	a.cPasswordEntry.SetPlaceHolder("Confirm password")
	a.cPasswordEntry.OnChanged = func(text string) {
		a.State.CPassword = text
		a.updateValidation()
		a.updateUIState()
	}

	a.validIndicator = NewValidationIndicator()
	confirmRow := container.NewBorder(nil, nil, nil, a.validIndicator, a.cPasswordEntry)

	return container.NewVBox(
		widget.NewLabel("Password:"),
		buttonRow1,
		buttonRow2,
		passwordRow,
		widget.NewLabel("Confirm password:"),
		confirmRow,
	)
}

// buildMobileKeyfilesSection creates the keyfiles section for mobile
func (a *App) buildMobileKeyfilesSection() fyne.CanvasObject {
	a.keyfileEditBtn = widget.NewButton("Edit", func() {
		a.showKeyfileModal()
	})

	a.keyfileCreateBtn = widget.NewButton("Create", func() {
		a.createKeyfile()
	})

	a.keyfileLabel = widget.NewLabel(keyfileDisplayLabel(
		a.State.Keyfile,
		len(a.State.Keyfiles),
		keyfileApplicable(a.State.Mode, a.State.Keyfile, a.State.Deniability),
	))
	a.keyfileLabel.Wrapping = fyne.TextWrapWord

	buttonRow := container.NewGridWithColumns(2, a.keyfileEditBtn, a.keyfileCreateBtn)

	return container.NewVBox(
		widget.NewLabel("Keyfiles:"),
		buttonRow,
		a.keyfileLabel,
	)
}

// buildMobileCommentsSection creates the comments section for mobile
func (a *App) buildMobileCommentsSection() fyne.CanvasObject {
	a.commentsLabel = widget.NewLabel(commentsLabelText(a.State.Mode))
	a.commentsEntry = widget.NewEntry()
	a.commentsEntry.SetPlaceHolder("Comments (not encrypted)")
	a.commentsEntry.MultiLine = true
	a.commentsEntry.OnChanged = func(text string) {
		if a.State.Mode == "decrypt" {
			snap := a.State.UISnapshot()
			displayText := commentsDisplayText(snap.Mode, snap.Comments, snap.CommentsPreviewState)
			if text != displayText {
				a.commentsEntry.SetText(displayText)
			}
			return
		}
		a.State.Comments = text
	}

	return container.NewVBox(
		a.commentsLabel,
		a.commentsEntry,
	)
}

// updateMobileAdvancedSection updates advanced options for mobile
func (a *App) updateMobileAdvancedSection() {
	a.advancedContainer.RemoveAll()

	if a.State.Mode != "decrypt" {
		a.buildMobileEncryptOptions()
	} else {
		a.buildMobileDecryptOptions()
	}

	// IMPORTANT: Update disable state for newly created checkboxes
	// This ensures checkboxes are disabled until user enters credentials
	a.updateAdvancedDisableState()

	a.advancedContainer.Refresh()
}

// buildMobileEncryptOptions creates encrypt options for mobile
func (a *App) buildMobileEncryptOptions() {
	// Checkboxes with more spacing
	a.paranoidCheck = ttwidget.NewCheck("Paranoid mode", func(checked bool) {
		a.State.Paranoid = checked
	})
	a.paranoidCheck.SetChecked(a.State.Paranoid)

	a.compressCheck = ttwidget.NewCheck("Compress files", func(checked bool) {
		a.State.Compress = checked
		// Auto-toggle .zip suffix in output filename
		a.updateOutputFileForCompress(checked)
	})
	a.compressCheck.SetChecked(a.State.Compress)

	a.reedSolomonCheck = ttwidget.NewCheck("Reed-Solomon", func(checked bool) {
		a.State.ReedSolomon = checked
	})
	a.reedSolomonCheck.SetChecked(a.State.ReedSolomon)

	a.deleteCheck = ttwidget.NewCheck("Delete files", func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetChecked(a.State.Delete)

	a.deniabilityCheck = ttwidget.NewCheck("Deniability", func(checked bool) {
		a.State.Deniability = checked
		a.updateUIState()
	})
	a.deniabilityCheck.SetChecked(a.State.Deniability)

	a.recursivelyCheck = ttwidget.NewCheck("Recursively", func(checked bool) {
		a.State.Recursively = checked
		if checked {
			a.State.Compress = false
			if a.compressCheck != nil {
				a.compressCheck.SetChecked(false)
			}
		}
		a.updateUIState()
	})
	a.recursivelyCheck.SetChecked(a.State.Recursively)

	// Grid layout - 2 columns
	row1 := container.NewGridWithColumns(2, a.paranoidCheck, a.compressCheck)
	row2 := container.NewGridWithColumns(2, a.reedSolomonCheck, a.deleteCheck)
	row3 := container.NewGridWithColumns(2, a.deniabilityCheck, a.recursivelyCheck)

	// Split section
	a.splitCheck = ttwidget.NewCheck("Split:", func(checked bool) {
		a.State.Split = checked
		a.updateUIState()
	})
	a.splitCheck.SetChecked(a.State.Split)

	a.splitSizeEntry = widget.NewEntry()
	a.splitSizeEntry.SetPlaceHolder("Size")
	a.splitSizeEntry.SetText(a.State.SplitSize)
	a.splitSizeEntry.OnChanged = func(text string) {
		a.State.SplitSize = text
		a.State.Split = text != ""
		if a.splitCheck != nil {
			a.splitCheck.SetChecked(a.State.Split)
		}
		a.updateUIState()
	}

	a.splitUnitSelect = ttwidget.NewSelect(a.State.SplitUnits, func(selected string) {
		for i, unit := range a.State.SplitUnits {
			if unit == selected {
				// #nosec G115 -- i is bounded by SplitUnits length (5 items: KiB, MiB, GiB, TiB, Total)
				a.State.SplitSelected = int32(i)
				break
			}
		}
	})
	a.splitUnitSelect.SetSelectedIndex(int(a.State.SplitSelected))

	splitRow := container.NewBorder(nil, nil, a.splitCheck, a.splitUnitSelect, a.splitSizeEntry)

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
	a.advancedContainer.Add(row3)
	a.advancedContainer.Add(splitRow)
}

// buildMobileDecryptOptions creates decrypt options for mobile
func (a *App) buildMobileDecryptOptions() {
	a.forceDecryptCheck = ttwidget.NewCheck("Force decrypt", func(checked bool) {
		a.State.Keep = checked
	})
	a.forceDecryptCheck.SetChecked(a.State.Keep)

	a.verifyFirstCheck = ttwidget.NewCheck("Verify first", func(checked bool) {
		a.State.VerifyFirst = checked
	})
	a.verifyFirstCheck.SetChecked(a.State.VerifyFirst)

	a.deleteCheck = ttwidget.NewCheck("Delete encrypted", func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetChecked(a.State.Delete)

	row1 := container.NewGridWithColumns(2, a.forceDecryptCheck, a.verifyFirstCheck)
	row2 := container.NewGridWithColumns(2, a.deleteCheck, widget.NewLabel(""))

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
}

// buildMobileOutputSection creates the output section for mobile
func (a *App) buildMobileOutputSection() fyne.CanvasObject {
	outputEntry := widget.NewLabel("")
	// Truncate long filenames with ellipsis to prevent excessive wrapping
	outputEntry.Truncation = fyne.TextTruncateEllipsis
	a.outputEntry = outputEntry

	a.changeBtn = widget.NewButton("Change", func() {
		a.changeOutputFile()
	})

	return container.NewVBox(
		widget.NewLabel("Save output as:"),
		outputEntry,
		a.changeBtn,
	)
}
