// Package ui provides the Picocrypt NG graphical user interface using Fyne.
//
// The UI is designed to match the original audited Picocrypt layout exactly, ensuring
// users familiar with the original application can transition seamlessly. Key features:
//
//   - Drag-and-drop file/folder selection
//   - Password strength indicator (using zxcvbn algorithm)
//   - Keyfile management (ordered and unordered modes)
//   - Advanced options: paranoid mode, Reed-Solomon, deniability, compression
//   - Real-time progress reporting with speed and ETA
//   - Automatic output file naming and format detection
//
// The UI state is managed by internal/app.State, which centralizes all application
// state in a thread-safe manner. Encryption/decryption operations run in goroutines
// with progress reported via the ProgressReporter interface.
package ui

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"

	"fyne.io/fyne/v2"
	fyneApp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	extDialog "github.com/Picocrypt/dialog"
	"github.com/Picocrypt/zxcvbn-go"
)

//go:embed icon.svg
var appIconData []byte

// UI dimensions matching original giu implementation
const (
	windowWidth         = 318
	windowHeightEncrypt = 510 // Full height for encrypt mode (more options)
	windowHeightDecrypt = 430 // Reduced height for decrypt mode (fewer options)
	buttonWidth         = 54
	padding             = 4 // Reduced from 8 to match compact theme
	contentWidth        = windowWidth - padding*2
)

// App represents the main UI application.
type App struct {
	fyneApp fyne.App
	Window  fyne.Window
	Version string
	DPI     float32

	// Application state
	State *app.State

	// Reed-Solomon codecs
	rsCodecs *encoding.RSCodecs

	// Cancellation flag (atomic for thread safety across goroutines)
	cancelled atomic.Bool

	// UI widgets that need to be updated
	inputLabel        *widget.Label
	clearButton       *widget.Button
	mainContent       *fyne.Container
	passwordEntry     *PasswordEntry
	cPasswordEntry    *PasswordEntry
	strengthIndicator *PasswordStrengthIndicator
	validIndicator    *ValidationIndicator
	keyfileLabel      *widget.Label
	commentsLabel     *widget.Label
	commentsEntry     *widget.Entry
	advancedContainer *fyne.Container
	outputEntry       *widget.Label
	startButton       *widget.Button
	statusLabel       *ColoredLabel

	// Password buttons
	showHideBtn *widget.Button
	clearPwdBtn *widget.Button
	copyBtn     *widget.Button
	pasteBtn    *widget.Button
	createBtn   *widget.Button

	// Keyfile buttons
	keyfileEditBtn   *widget.Button
	keyfileCreateBtn *widget.Button

	// Output section
	changeBtn *widget.Button

	// Advanced options (encrypt mode)
	paranoidCheck    *widget.Check
	compressCheck    *widget.Check
	reedSolomonCheck *widget.Check
	deleteCheck      *widget.Check
	deniabilityCheck *widget.Check
	recursivelyCheck *widget.Check
	splitCheck       *widget.Check
	splitSizeEntry   *widget.Entry
	splitUnitSelect  *widget.Select

	// Advanced options (decrypt mode)
	forceDecryptCheck *widget.Check
	deleteVolumeCheck *widget.Check
	autoUnzipCheck    *widget.Check
	sameLevelCheck    *widget.Check

	// Modals
	passgenModal   dialog.Dialog
	keyfileModal   dialog.Dialog
	overwriteModal dialog.Dialog
	progressModal  dialog.Dialog

	// Progress widgets
	progressBar    *widget.ProgressBar
	progressLabel  *widget.Label
	progressStatus *widget.Label
	cancelButton   *widget.Button
}

// NewApp creates a new UI application.
func NewApp(version string) (*App, error) {
	rsCodecs, err := encoding.NewRSCodecs()
	if err != nil {
		return nil, err
	}

	state := app.NewState()
	state.RSCodecs = rsCodecs

	return &App{
		Version:  version,
		State:    state,
		rsCodecs: rsCodecs,
		DPI:      1.0,
	}, nil
}

// Run starts the UI application.
func (a *App) Run() {
	// Always create a new Fyne app - don't use CurrentApp() as it may not exist
	a.fyneApp = fyneApp.New()

	// Apply compact theme to match original Picocrypt look
	a.fyneApp.Settings().SetTheme(NewCompactTheme())

	// Set application icon (embedded SVG)
	appIcon := fyne.NewStaticResource("icon.svg", appIconData)
	a.fyneApp.SetIcon(appIcon)

	// Create main window with fixed size (starts with encrypt height)
	a.Window = a.fyneApp.NewWindow("Picocrypt NG " + a.Version[1:])
	a.Window.SetIcon(appIcon)
	a.Window.SetFixedSize(true)
	a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))

	// Initialize dialog package
	extDialog.Init()

	// Set clipboard callback for state
	// Must use fyne.Do() since this may be called from goroutines (e.g., GenPassword)
	a.State.SetClipboard = func(text string) {
		fyne.Do(func() {
			a.Window.Clipboard().SetContent(text)
		})
	}

	// Set close callback to prevent closing during operations
	a.Window.SetCloseIntercept(func() {
		if !a.State.Working && !a.State.ShowProgress {
			a.Window.Close()
		}
	})

	// Build UI
	content := a.buildUI()

	// Set up drag and drop
	a.Window.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		paths := make([]string, len(uris))
		for i, uri := range uris {
			paths[i] = uri.Path()
		}
		a.onDrop(paths)
	})

	// Set up Enter key handler
	if deskCanvas, ok := a.Window.Canvas().(desktop.Canvas); ok {
		deskCanvas.SetOnKeyDown(func(event *fyne.KeyEvent) {
			if event.Name == fyne.KeyReturn || event.Name == fyne.KeyEnter {
				a.onClickStart()
			}
		})
	}

	a.Window.SetContent(content)
	a.Window.ShowAndRun()
}

// fixedWidthButton creates a button with fixed width.
func fixedWidthButton(label string, width float32, onTapped func()) *fyne.Container {
	btn := widget.NewButton(label, onTapped)
	return container.New(&fixedWidthLayout{width: width}, btn)
}

// fixedWidthLayout is a layout that forces a fixed width.
type fixedWidthLayout struct {
	width float32
}

func (f *fixedWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(f.width, 0)
	}
	min := objects[0].MinSize()
	return fyne.NewSize(f.width, min.Height)
}

func (f *fixedWidthLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, obj := range objects {
		obj.Resize(fyne.NewSize(f.width, size.Height))
		obj.Move(fyne.NewPos(0, 0))
	}
}

// buildUI creates the main UI layout.
func (a *App) buildUI() fyne.CanvasObject {
	// Input label with Clear button
	a.inputLabel = widget.NewLabel(a.State.InputLabel)
	a.inputLabel.Wrapping = fyne.TextWrapWord
	a.clearButton = widget.NewButton("Clear", a.resetUI)
	// MediumImportance gives the button a visible border
	a.clearButton.Importance = widget.MediumImportance

	headerRow := container.NewBorder(nil, nil, nil, a.clearButton, a.inputLabel)

	// Password section
	passwordSection := a.buildPasswordSection()

	// Keyfiles section
	keyfilesSection := a.buildKeyfilesSection()

	// Comments section
	commentsSection := a.buildCommentsSection()

	// Advanced section
	a.advancedContainer = container.NewVBox()
	a.updateAdvancedSection()

	// Output section
	outputSection := a.buildOutputSection()

	// Start button and status
	a.startButton = widget.NewButton(a.State.StartLabel, a.onClickStart)
	a.startButton.Importance = widget.HighImportance

	a.statusLabel = NewColoredLabel(a.State.MainStatus, a.State.MainStatusColor)

	// Main content container
	a.mainContent = container.NewVBox(
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

	// Full layout with padding
	fullLayout := container.NewVBox(
		headerRow,
		widget.NewSeparator(),
		a.mainContent,
	)

	// Add padding
	padded := container.NewPadded(fullLayout)

	a.updateUIState()

	return padded
}

// buildPasswordSection creates the password input section.
func (a *App) buildPasswordSection() fyne.CanvasObject {
	// Password buttons row
	a.showHideBtn = widget.NewButton(a.State.PasswordStateLabel, func() {
		a.State.TogglePasswordVisibility()
		a.showHideBtn.SetText(a.State.PasswordStateLabel)
		a.passwordEntry.SetHidden(a.State.IsPasswordHidden())
		a.cPasswordEntry.SetHidden(a.State.IsPasswordHidden())
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
		a.Window.Clipboard().SetContent(a.State.Password)
	})

	a.pasteBtn = widget.NewButton("Paste", func() {
		text := a.Window.Clipboard().Content()
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

	// Use adaptive grid that fills available space evenly
	buttonRow := container.NewGridWithColumns(5,
		a.showHideBtn, a.clearPwdBtn, a.copyBtn, a.pasteBtn, a.createBtn,
	)

	// Password input with strength indicator
	a.passwordEntry = NewPasswordEntry()
	a.passwordEntry.SetPlaceHolder("Password")
	a.passwordEntry.OnChanged = func(text string) {
		a.State.Password = text
		a.updatePasswordStrength()
		a.updateValidation()
		a.updateUIState() // Update button states based on password
	}

	a.strengthIndicator = NewPasswordStrengthIndicator()

	passwordRow := container.NewBorder(nil, nil, nil, a.strengthIndicator, a.passwordEntry)

	// Confirm password
	a.cPasswordEntry = NewPasswordEntry()
	a.cPasswordEntry.SetPlaceHolder("Confirm password")
	a.cPasswordEntry.OnChanged = func(text string) {
		a.State.CPassword = text
		a.updateValidation()
		a.updateUIState() // Update button states based on password match
	}

	a.validIndicator = NewValidationIndicator()

	confirmRow := container.NewBorder(nil, nil, nil, a.validIndicator, a.cPasswordEntry)

	return container.NewVBox(
		widget.NewLabel("Password:"),
		buttonRow,
		passwordRow,
		widget.NewLabel("Confirm password:"),
		confirmRow,
	)
}

// buildKeyfilesSection creates the keyfiles input section.
func (a *App) buildKeyfilesSection() fyne.CanvasObject {
	a.keyfileEditBtn = widget.NewButton("Edit", func() {
		a.showKeyfileModal()
	})

	a.keyfileCreateBtn = widget.NewButton("Create", func() {
		a.createKeyfile()
	})

	a.keyfileLabel = widget.NewLabel(a.State.KeyfileLabel)

	// Layout: "Keyfiles:" Edit Create [label fills rest]
	return container.NewHBox(
		widget.NewLabel("Keyfiles:"),
		a.keyfileEditBtn,
		a.keyfileCreateBtn,
		a.keyfileLabel,
	)
}

// buildCommentsSection creates the comments input section.
func (a *App) buildCommentsSection() fyne.CanvasObject {
	a.commentsLabel = widget.NewLabel(a.State.CommentsLabel)
	a.commentsEntry = widget.NewEntry()
	a.commentsEntry.SetPlaceHolder("Comments (not encrypted)")
	a.commentsEntry.OnChanged = func(text string) {
		// In decrypt mode, comments are read-only - revert any changes
		if a.State.Mode == "decrypt" {
			if text != a.State.Comments {
				a.commentsEntry.SetText(a.State.Comments)
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

// buildOutputSection creates the output file section.
func (a *App) buildOutputSection() fyne.CanvasObject {
	a.outputEntry = widget.NewLabel("")

	// Create a disabled entry style appearance
	outputBg := canvas.NewRectangle(theme.InputBackgroundColor())
	outputBg.CornerRadius = theme.InputRadiusSize()
	outputWithBg := container.NewStack(outputBg, container.NewPadded(a.outputEntry))

	a.changeBtn = widget.NewButton("Change", func() {
		a.changeOutputFile()
	})

	row := container.NewBorder(nil, nil, nil, a.changeBtn, outputWithBg)

	return container.NewVBox(
		widget.NewLabel("Save output as:"),
		row,
	)
}

// updateAdvancedSection updates the advanced options based on mode.
func (a *App) updateAdvancedSection() {
	a.advancedContainer.RemoveAll()

	if a.State.Mode != "decrypt" {
		a.buildEncryptOptions()
		// Resize window for encrypt mode (more options)
		if a.Window != nil {
			a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
		}
	} else {
		a.buildDecryptOptions()
		// Resize window for decrypt mode (fewer options)
		if a.Window != nil {
			a.Window.Resize(fyne.NewSize(windowWidth, windowHeightDecrypt))
		}
	}

	a.advancedContainer.Refresh()
}

// buildEncryptOptions creates encrypt mode options.
func (a *App) buildEncryptOptions() {
	// Row 1: Paranoid + Compress
	a.paranoidCheck = widget.NewCheck("Paranoid mode", func(checked bool) {
		a.State.Paranoid = checked
	})
	a.paranoidCheck.SetChecked(a.State.Paranoid)

	a.compressCheck = widget.NewCheck("Compress files", func(checked bool) {
		a.State.Compress = checked
	})
	a.compressCheck.SetChecked(a.State.Compress)

	row1 := container.NewGridWithColumns(2, a.paranoidCheck, a.compressCheck)

	// Row 2: Reed-Solomon + Delete files
	a.reedSolomonCheck = widget.NewCheck("Reed-Solomon", func(checked bool) {
		a.State.ReedSolomon = checked
	})
	a.reedSolomonCheck.SetChecked(a.State.ReedSolomon)

	a.deleteCheck = widget.NewCheck("Delete files", func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteCheck.SetChecked(a.State.Delete)

	row2 := container.NewGridWithColumns(2, a.reedSolomonCheck, a.deleteCheck)

	// Row 3: Deniability + Recursively
	a.deniabilityCheck = widget.NewCheck("Deniability", func(checked bool) {
		a.State.Deniability = checked
		a.updateUIState()
	})
	a.deniabilityCheck.SetChecked(a.State.Deniability)

	a.recursivelyCheck = widget.NewCheck("Recursively", func(checked bool) {
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

	row3 := container.NewGridWithColumns(2, a.deniabilityCheck, a.recursivelyCheck)

	// Row 4: Split into chunks
	a.splitCheck = widget.NewCheck("Split:", func(checked bool) {
		a.State.Split = checked
		a.updateUIState() // Update status to show increased disk space requirement
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
		a.updateUIState() // Update status to show increased disk space requirement
	}

	a.splitUnitSelect = widget.NewSelect(a.State.SplitUnits, func(selected string) {
		for i, unit := range a.State.SplitUnits {
			if unit == selected {
				a.State.SplitSelected = int32(i)
				break
			}
		}
	})
	a.splitUnitSelect.SetSelectedIndex(int(a.State.SplitSelected))

	splitRow := container.NewBorder(nil, nil,
		a.splitCheck,
		a.splitUnitSelect,
		a.splitSizeEntry,
	)

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
	a.advancedContainer.Add(row3)
	a.advancedContainer.Add(splitRow)
}

// buildDecryptOptions creates decrypt mode options.
func (a *App) buildDecryptOptions() {
	// Row 1: Force decrypt + Delete volume
	a.forceDecryptCheck = widget.NewCheck("Force decrypt", func(checked bool) {
		a.State.Keep = checked
	})
	a.forceDecryptCheck.SetChecked(a.State.Keep)

	a.deleteVolumeCheck = widget.NewCheck("Delete volume", func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteVolumeCheck.SetChecked(a.State.Delete)

	row1 := container.NewGridWithColumns(2, a.forceDecryptCheck, a.deleteVolumeCheck)

	// Row 2: Auto unzip + Same level
	a.autoUnzipCheck = widget.NewCheck("Auto unzip", func(checked bool) {
		a.State.AutoUnzip = checked
		if !checked {
			a.State.SameLevel = false
			if a.sameLevelCheck != nil {
				a.sameLevelCheck.SetChecked(false)
			}
		}
		a.updateUIState()
	})
	a.autoUnzipCheck.SetChecked(a.State.AutoUnzip)

	a.sameLevelCheck = widget.NewCheck("Same level", func(checked bool) {
		a.State.SameLevel = checked
	})
	a.sameLevelCheck.SetChecked(a.State.SameLevel)

	row2 := container.NewGridWithColumns(2, a.autoUnzipCheck, a.sameLevelCheck)

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)

	// Disable auto unzip if not a zip file
	if !strings.HasSuffix(a.State.InputFile, ".zip.pcv") {
		a.autoUnzipCheck.Disable()
		a.sameLevelCheck.Disable()
	}

	// Disable same level if auto unzip is not checked
	if !a.State.AutoUnzip {
		a.sameLevelCheck.Disable()
	}

	// Disable force decrypt if deniability
	if a.State.Deniability {
		a.forceDecryptCheck.Disable()
	}
}

// updatePasswordStrength updates the password strength indicator.
func (a *App) updatePasswordStrength() {
	a.State.PasswordStrength = zxcvbn.PasswordStrength(a.State.Password, nil).Score
	if a.strengthIndicator != nil {
		a.strengthIndicator.SetStrength(a.State.PasswordStrength)
		a.strengthIndicator.SetVisible(a.State.Password != "")
		a.strengthIndicator.SetDecryptMode(a.State.Mode == "decrypt")
	}
}

// updateValidation updates the password validation indicator.
func (a *App) updateValidation() {
	if a.validIndicator == nil {
		return
	}
	visible := a.State.Password != "" && a.State.CPassword != "" && a.State.Mode != "decrypt"
	valid := a.State.Password == a.State.CPassword
	a.validIndicator.SetVisible(visible)
	a.validIndicator.SetValid(valid)
}

// refreshUI updates all UI elements to reflect current state.
// This is the main entry point for UI updates from the main thread.
func (a *App) refreshUI() {
	a.updateUIState()
}

// refreshAdvanced rebuilds the advanced section for the current mode.
func (a *App) refreshAdvanced() {
	a.updateAdvancedSection()
}

// updateUIState updates the enabled/disabled state of all UI elements.
// This mirrors the exact logic from the original giu implementation.
func (a *App) updateUIState() {
	hasFiles := len(a.State.AllFiles) > 0 || len(a.State.OnlyFiles) > 0 || len(a.State.OnlyFolders) > 0
	isScanning := a.State.Scanning

	// Main content disabled - matches giu: (len(allFiles) == 0 && len(onlyFiles) == 0) || scanning
	// Note: we also check onlyFolders for consistency
	mainDisabled := !hasFiles || isScanning

	// Clear button - matches giu line 461
	if a.clearButton != nil {
		if mainDisabled {
			a.clearButton.Disable()
		} else {
			a.clearButton.Enable()
		}
	}

	// Password section - all buttons/inputs disabled when mainDisabled (giu line 469)
	if a.passwordEntry != nil {
		if mainDisabled {
			a.passwordEntry.Disable()
		} else {
			a.passwordEntry.Enable()
		}
	}

	if a.showHideBtn != nil {
		if mainDisabled {
			a.showHideBtn.Disable()
		} else {
			a.showHideBtn.Enable()
		}
	}

	if a.clearPwdBtn != nil {
		if mainDisabled {
			a.clearPwdBtn.Disable()
		} else {
			a.clearPwdBtn.Enable()
		}
	}

	if a.copyBtn != nil {
		if mainDisabled {
			a.copyBtn.Disable()
		} else {
			a.copyBtn.Enable()
		}
	}

	if a.pasteBtn != nil {
		if mainDisabled {
			a.pasteBtn.Disable()
		} else {
			a.pasteBtn.Enable()
		}
	}

	// Create password button - disabled in decrypt mode (giu line 508)
	if a.createBtn != nil {
		if mainDisabled || a.State.Mode == "decrypt" {
			a.createBtn.Disable()
		} else {
			a.createBtn.Enable()
		}
	}

	// Confirm password - disabled when password == "" || mode == "decrypt" (giu line 542)
	// This is NESTED inside mainDisabled block, so we check both
	if a.cPasswordEntry != nil {
		if mainDisabled || a.State.Password == "" || a.State.Mode == "decrypt" {
			a.cPasswordEntry.Disable()
		} else {
			a.cPasswordEntry.Enable()
		}
	}

	// Keyfile section - disabled when mode == "decrypt" && !keyfile && !deniability (giu line 567)
	keyfileDisabled := mainDisabled || (a.State.Mode == "decrypt" && !a.State.Keyfile && !a.State.Deniability)
	if a.keyfileEditBtn != nil {
		if keyfileDisabled {
			a.keyfileEditBtn.Disable()
		} else {
			a.keyfileEditBtn.Enable()
		}
	}
	// Keyfile Create - disabled in decrypt mode (giu line 582)
	if a.keyfileCreateBtn != nil {
		if mainDisabled || a.State.Mode == "decrypt" {
			a.keyfileCreateBtn.Disable()
		} else {
			a.keyfileCreateBtn.Enable()
		}
	}

	// Comments section - complex nested logic from giu lines 632-633:
	// Outer: mode != "decrypt" && ((len(keyfiles) == 0 && password == "") || (password != cpassword)) || deniability
	// Inner: mode == "decrypt" && (comments == "" || comments == "Comments are corrupted")
	commentsOuterDisabled := (a.State.Mode != "decrypt" &&
		((len(a.State.Keyfiles) == 0 && a.State.Password == "") ||
			(a.State.Password != a.State.CPassword))) ||
		a.State.Deniability
	commentsInnerDisabled := a.State.Mode == "decrypt" &&
		(a.State.Comments == "" || a.State.Comments == "Comments are corrupted")

	if a.commentsEntry != nil {
		// In decrypt mode with valid comments, keep entry enabled but read-only
		// (OnChanged will prevent actual changes). This keeps text visible, not pale.
		if a.State.Mode == "decrypt" && a.State.Comments != "" && a.State.Comments != "Comments are corrupted" {
			a.commentsEntry.Enable() // Keep text visible (not pale)
		} else if mainDisabled || commentsOuterDisabled || commentsInnerDisabled || a.State.CommentsDisabled {
			a.commentsEntry.Disable()
		} else {
			a.commentsEntry.Enable()
		}
	}

	// Advanced section and Start button - giu line 650:
	// (len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword)
	hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
	passwordsMatch := a.State.Mode != "encrypt" || a.State.Password == a.State.CPassword
	advancedAndStartDisabled := !hasCredentials || !passwordsMatch

	// Update advanced section checkboxes/inputs
	a.updateAdvancedDisableState()

	// Start button - MUST be disabled when no credentials or passwords don't match
	if a.startButton != nil {
		label := a.State.StartLabel
		if a.State.Recursively {
			label = "Process"
		}
		a.startButton.SetText(label)

		if mainDisabled || advancedAndStartDisabled {
			a.startButton.Disable()
		} else {
			a.startButton.Enable()
		}
	}

	// Update output display
	if a.outputEntry != nil {
		outputDisplay := ""
		if a.State.OutputFile != "" {
			outputDisplay = filepath.Base(a.State.OutputFile)
			if a.State.Split {
				outputDisplay += ".*"
			}
			if a.State.Recursively {
				outputDisplay = "(multiple values)"
			}
		}
		a.outputEntry.SetText(outputDisplay)
	}

	// Change button - disabled when recursively (giu line 724)
	if a.changeBtn != nil {
		if mainDisabled || advancedAndStartDisabled || a.State.Recursively {
			a.changeBtn.Disable()
		} else {
			a.changeBtn.Enable()
		}
	}

	// Update status
	if a.statusLabel != nil {
		statusText := a.State.MainStatus
		if a.State.MainStatus == "Ready" && a.State.RequiredFreeSpace > 0 {
			multiplier := 1
			if len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 {
				multiplier++
			}
			if a.State.Deniability {
				multiplier++
			}
			if a.State.Split {
				multiplier++
			}
			if a.State.Recombine {
				multiplier++
			}
			if a.State.AutoUnzip {
				multiplier++
			}
			statusText = "Ready (ensure >" + util.Sizeify(a.State.RequiredFreeSpace*int64(multiplier)) + " free)"
		}
		a.statusLabel.SetText(statusText)
		a.statusLabel.SetColor(a.State.MainStatusColor)
	}

	// Update labels
	if a.inputLabel != nil {
		a.inputLabel.SetText(a.State.InputLabel)
	}

	if a.keyfileLabel != nil {
		a.keyfileLabel.SetText(a.State.KeyfileLabel)
	}

	if a.commentsLabel != nil {
		a.commentsLabel.SetText(a.State.CommentsLabel)
	}
}

// updateAdvancedDisableState updates the disable state of advanced options.
func (a *App) updateAdvancedDisableState() {
	hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
	passwordsMatch := a.State.Mode != "encrypt" || a.State.Password == a.State.CPassword
	advancedDisabled := !hasCredentials || !passwordsMatch

	if a.State.Mode != "decrypt" {
		// Encrypt mode options
		if a.compressCheck != nil {
			if advancedDisabled || a.State.Recursively || (len(a.State.AllFiles) <= 1 && len(a.State.OnlyFolders) == 0) {
				a.compressCheck.Disable()
			} else {
				a.compressCheck.Enable()
			}
		}

		if a.recursivelyCheck != nil {
			if advancedDisabled || (len(a.State.AllFiles) <= 1 && len(a.State.OnlyFolders) == 0) {
				a.recursivelyCheck.Disable()
			} else {
				a.recursivelyCheck.Enable()
			}
		}

		if a.paranoidCheck != nil {
			if advancedDisabled {
				a.paranoidCheck.Disable()
			} else {
				a.paranoidCheck.Enable()
			}
		}

		if a.reedSolomonCheck != nil {
			if advancedDisabled {
				a.reedSolomonCheck.Disable()
			} else {
				a.reedSolomonCheck.Enable()
			}
		}

		if a.deleteCheck != nil {
			if advancedDisabled {
				a.deleteCheck.Disable()
			} else {
				a.deleteCheck.Enable()
			}
		}

		if a.deniabilityCheck != nil {
			if advancedDisabled {
				a.deniabilityCheck.Disable()
			} else {
				a.deniabilityCheck.Enable()
			}
		}

		if a.splitCheck != nil {
			if advancedDisabled {
				a.splitCheck.Disable()
			} else {
				a.splitCheck.Enable()
			}
		}

		if a.splitSizeEntry != nil {
			if advancedDisabled {
				a.splitSizeEntry.Disable()
			} else {
				a.splitSizeEntry.Enable()
			}
		}

		if a.splitUnitSelect != nil {
			if advancedDisabled {
				a.splitUnitSelect.Disable()
			} else {
				a.splitUnitSelect.Enable()
			}
		}
	} else {
		// Decrypt mode options
		if a.forceDecryptCheck != nil {
			if advancedDisabled || a.State.Deniability {
				a.forceDecryptCheck.Disable()
			} else {
				a.forceDecryptCheck.Enable()
			}
		}

		if a.deleteVolumeCheck != nil {
			if advancedDisabled {
				a.deleteVolumeCheck.Disable()
			} else {
				a.deleteVolumeCheck.Enable()
			}
		}

		if a.autoUnzipCheck != nil {
			if advancedDisabled || !strings.HasSuffix(a.State.InputFile, ".zip.pcv") {
				a.autoUnzipCheck.Disable()
			} else {
				a.autoUnzipCheck.Enable()
			}
		}

		if a.sameLevelCheck != nil {
			if advancedDisabled || !a.State.AutoUnzip {
				a.sameLevelCheck.Disable()
			} else {
				a.sameLevelCheck.Enable()
			}
		}
	}
}

// CreateReporter creates a UIReporter for progress updates.
func (a *App) CreateReporter() *app.UIReporter {
	return app.NewUIReporter(
		func(text string) {
			a.State.PopupStatus = text
			fyne.Do(func() {
				if a.progressStatus != nil {
					a.progressStatus.SetText(text)
				}
			})
		},
		func(fraction float32, info string) {
			a.State.Progress = fraction
			a.State.ProgressInfo = info
			fyne.Do(func() {
				if a.progressBar != nil {
					a.progressBar.SetValue(float64(fraction))
				}
				if a.progressLabel != nil {
					a.progressLabel.SetText(info)
				}
			})
		},
		func(can bool) {
			a.State.CanCancel = can
			fyne.Do(func() {
				if a.cancelButton != nil {
					if can {
						a.cancelButton.Enable()
					} else {
						a.cancelButton.Disable()
					}
				}
			})
		},
		func() {
			fyne.Do(func() {
				a.updateUIState()
			})
		},
		func() bool {
			return !a.State.Working
		},
	)
}

// createKeyfile creates a new random keyfile.
func (a *App) createKeyfile() {
	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}

	f := extDialog.File().Title("Choose where to save the keyfile")
	if startDir != "" {
		f.SetStartDir(startDir)
	}
	f.SetInitFilename("keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin")

	file, err := f.Save()
	if file == "" || err != nil {
		return
	}

	fout, err := os.Create(file)
	if err != nil {
		a.State.MainStatus = "Failed to create keyfile"
		a.State.MainStatusColor = util.RED
		a.updateUIState()
		return
	}

	data := make([]byte, 32)
	if n, err := rand.Read(data); err != nil || n != 32 {
		_ = fout.Close()
		a.State.MainStatus = "Failed to generate keyfile"
		a.State.MainStatusColor = util.RED
		a.updateUIState()
		return
	}

	n, err := fout.Write(data)
	if err != nil || n != 32 {
		_ = fout.Close()
		a.State.MainStatus = "Failed to write keyfile"
		a.State.MainStatusColor = util.RED
		a.updateUIState()
		return
	}

	if err := fout.Close(); err != nil {
		a.State.MainStatus = "Failed to close keyfile"
		a.State.MainStatusColor = util.RED
		a.updateUIState()
		return
	}

	a.State.MainStatus = "Ready"
	a.State.MainStatusColor = util.WHITE
	a.updateUIState()
}

// changeOutputFile opens a dialog to change the output file path.
func (a *App) changeOutputFile() {
	f := extDialog.File().Title("Choose where to save the output. Don't include extensions")

	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}
	if startDir != "" {
		f.SetStartDir(startDir)
	}

	// Prefill filename
	tmp := strings.TrimSuffix(filepath.Base(a.State.OutputFile), ".pcv")
	f.SetInitFilename(strings.TrimSuffix(tmp, filepath.Ext(tmp)))
	if a.State.Mode == "encrypt" && (len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 || a.State.Compress) {
		f.SetInitFilename("encrypted-" + strconv.Itoa(int(time.Now().Unix())))
	}

	file, err := f.Save()
	if file == "" || err != nil {
		return
	}
	file = filepath.Join(filepath.Dir(file), strings.Split(filepath.Base(file), ".")[0])

	// Add correct extensions
	if a.State.Mode == "encrypt" {
		if len(a.State.AllFiles) > 1 || len(a.State.OnlyFolders) > 0 || a.State.Compress {
			file += ".zip.pcv"
		} else {
			file += filepath.Ext(a.State.InputFile) + ".pcv"
		}
	} else {
		if strings.HasSuffix(a.State.InputFile, ".zip.pcv") {
			file += ".zip"
		} else {
			tmp := strings.TrimSuffix(filepath.Base(a.State.InputFile), ".pcv")
			file += filepath.Ext(tmp)
		}
	}

	a.State.OutputFile = file
	a.State.MainStatus = "Ready"
	a.State.MainStatusColor = util.WHITE
	a.updateUIState()
}

// onClickStart handles the Start button click.
func (a *App) onClickStart() {
	// Validate
	if a.State.Mode == "" {
		return
	}

	hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
	if !hasCredentials {
		return
	}

	if a.State.Mode == "encrypt" && a.State.Password != a.State.CPassword {
		return
	}

	// Check if output exists (skip check for recursive mode - each file has different output)
	if _, err := os.Stat(a.State.OutputFile); err == nil && !a.State.Recursively {
		a.showOverwriteModal()
		return
	}

	a.startWork()
}

// startWork begins the encryption/decryption operation.
func (a *App) startWork() {
	a.State.ShowProgress = true
	a.State.FastDecode = true
	a.State.CanCancel = true
	a.State.ModalID++
	a.cancelled.Store(false)

	a.showProgressModal()

	if !a.State.Recursively {
		// Normal mode: process single file/folder(s)
		go func() {
			a.doWork()
			a.State.Working = false
			a.State.ShowProgress = false
			fyne.Do(func() {
				if a.progressModal != nil {
					a.progressModal.Hide()
				}
				a.updateUIState()
			})
		}()
	} else {
		// Recursive mode: process each file individually
		a.startRecursiveWork()
	}
}

// doWork performs the encryption or decryption operation.
// Returns true if the operation completed successfully.
func (a *App) doWork() bool {
	a.State.Working = true
	reporter := a.CreateReporter()

	if a.State.Mode == "encrypt" {
		return a.doEncrypt(reporter)
	}
	return a.doDecrypt(reporter)
}

// startRecursiveWork handles batch processing of multiple files individually.
func (a *App) startRecursiveWork() {
	if len(a.State.AllFiles) == 0 {
		a.State.MainStatus = "No files to process"
		a.State.MainStatusColor = util.YELLOW
		a.State.Working = false
		a.State.ShowProgress = false
		fyne.Do(func() {
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateUIState()
		})
		return
	}

	// Store all settings before they get cleared by onDrop/resetUI
	savedPassword := a.State.Password
	savedKeyfile := a.State.Keyfile
	savedKeyfiles := make([]string, len(a.State.Keyfiles))
	copy(savedKeyfiles, a.State.Keyfiles)
	savedKeyfileOrdered := a.State.KeyfileOrdered
	savedKeyfileLabel := a.State.KeyfileLabel
	savedComments := a.State.Comments
	savedParanoid := a.State.Paranoid
	savedReedSolomon := a.State.ReedSolomon
	savedDeniability := a.State.Deniability
	savedSplit := a.State.Split
	savedSplitSize := a.State.SplitSize
	savedSplitSelected := a.State.SplitSelected
	savedDelete := a.State.Delete

	files := make([]string, len(a.State.AllFiles))
	copy(files, a.State.AllFiles)

	go func() {
		var failedCount int
		var successCount int

		for i, file := range files {
			a.State.PopupStatus = fmt.Sprintf("Processing file %d/%d...", i+1, len(files))
			fyne.Do(func() {
				if a.progressStatus != nil {
					a.progressStatus.SetText(a.State.PopupStatus)
				}
			})

			a.onDrop([]string{file})

			// Restore all saved settings
			a.State.Password = savedPassword
			a.State.CPassword = savedPassword
			a.State.Keyfile = savedKeyfile
			a.State.Keyfiles = make([]string, len(savedKeyfiles))
			copy(a.State.Keyfiles, savedKeyfiles)
			a.State.KeyfileOrdered = savedKeyfileOrdered
			a.State.KeyfileLabel = savedKeyfileLabel
			a.State.Comments = savedComments
			a.State.Paranoid = savedParanoid
			a.State.ReedSolomon = savedReedSolomon
			if a.State.Mode != "decrypt" {
				a.State.Deniability = savedDeniability
			}
			a.State.Split = savedSplit
			a.State.SplitSize = savedSplitSize
			a.State.SplitSelected = savedSplitSelected
			a.State.Delete = savedDelete

			if a.doWork() {
				successCount++
			} else {
				failedCount++
			}

			// Reset Working flag so next iteration's onDrop() isn't blocked
			// (onDrop has a guard to prevent race conditions during scanning/working)
			a.State.Working = false

			if a.cancelled.Load() {
				a.State.Working = false
				a.State.ShowProgress = false
				fyne.Do(func() {
					if a.progressModal != nil {
						a.progressModal.Hide()
					}
					a.updateUIState()
				})
				return
			}
		}

		a.State.Working = false
		a.State.ShowProgress = false

		if failedCount == 0 {
			a.State.MainStatus = fmt.Sprintf("Completed (%d files)", successCount)
			a.State.MainStatusColor = util.GREEN
		} else if successCount == 0 {
			a.State.MainStatus = fmt.Sprintf("Failed (all %d files)", failedCount)
			a.State.MainStatusColor = util.RED
		} else {
			a.State.MainStatus = fmt.Sprintf("Completed (%d ok, %d failed)", successCount, failedCount)
			a.State.MainStatusColor = util.YELLOW
		}

		fyne.Do(func() {
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateUIState()
		})
	}()
}

// doEncrypt performs encryption using the volume package.
func (a *App) doEncrypt(reporter *app.UIReporter) bool {
	var chunkUnit fileops.SplitUnit
	switch a.State.SplitSelected {
	case 0:
		chunkUnit = fileops.SplitUnitKiB
	case 1:
		chunkUnit = fileops.SplitUnitMiB
	case 2:
		chunkUnit = fileops.SplitUnitGiB
	case 3:
		chunkUnit = fileops.SplitUnitTiB
	case 4:
		chunkUnit = fileops.SplitUnitTotal
	}

	chunkSize := 1
	if a.State.SplitSize != "" {
		n, err := strconv.Atoi(a.State.SplitSize)
		if err != nil || n <= 0 {
			a.State.MainStatus = "Invalid split size"
			a.State.MainStatusColor = util.RED
			return false
		}
		chunkSize = n
	}

	shouldDelete := a.State.Delete

	req := &volume.EncryptRequest{
		InputFile:      a.State.InputFile,
		InputFiles:     a.State.AllFiles,
		OnlyFolders:    a.State.OnlyFolders,
		OnlyFiles:      a.State.OnlyFiles,
		OutputFile:     a.State.OutputFile,
		Password:       a.State.Password,
		Keyfiles:       a.State.Keyfiles,
		KeyfileOrdered: a.State.KeyfileOrdered,
		Comments:       a.State.Comments,
		Paranoid:       a.State.Paranoid,
		ReedSolomon:    a.State.ReedSolomon,
		Deniability:    a.State.Deniability,
		Compress:       a.State.Compress,
		Split:          a.State.Split,
		ChunkSize:      chunkSize,
		ChunkUnit:      chunkUnit,
		Reporter:       reporter,
		RSCodecs:       a.rsCodecs,
	}

	filesToDelete := make([]string, len(a.State.AllFiles))
	copy(filesToDelete, a.State.AllFiles)
	foldersToDelete := make([]string, len(a.State.OnlyFolders))
	copy(foldersToDelete, a.State.OnlyFolders)
	inputFileToDelete := a.State.InputFile

	err := volume.Encrypt(req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.MainStatus = err.Error()
			a.State.MainStatusColor = util.RED
		}
		return false
	}

	a.State.ResetUI()
	a.State.MainStatus = "Completed"
	a.State.MainStatusColor = util.GREEN

	if shouldDelete {
		var deleteErrors []string
		if len(filesToDelete) > 0 {
			for _, f := range filesToDelete {
				if err := os.Remove(f); err != nil {
					deleteErrors = append(deleteErrors, f)
				}
			}
			for _, f := range foldersToDelete {
				if err := os.RemoveAll(f); err != nil {
					deleteErrors = append(deleteErrors, f)
				}
			}
		} else {
			if err := os.Remove(inputFileToDelete); err != nil {
				deleteErrors = append(deleteErrors, inputFileToDelete)
			}
		}
		if len(deleteErrors) > 0 {
			a.State.MainStatus = "Completed (some files couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// doDecrypt performs decryption using the volume package.
func (a *App) doDecrypt(reporter *app.UIReporter) bool {
	kept := false

	shouldDelete := a.State.Delete
	recombine := a.State.Recombine
	inputFile := a.State.InputFile

	req := &volume.DecryptRequest{
		InputFile:    a.State.InputFile,
		OutputFile:   a.State.OutputFile,
		Password:     a.State.Password,
		Keyfiles:     a.State.Keyfiles,
		ForceDecrypt: a.State.Keep,
		AutoUnzip:    a.State.AutoUnzip,
		SameLevel:    a.State.SameLevel,
		Recombine:    a.State.Recombine,
		Deniability:  a.State.Deniability,
		Reporter:     reporter,
		RSCodecs:     a.rsCodecs,
		Kept:         &kept,
	}

	err := volume.Decrypt(req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.MainStatus = err.Error()
			a.State.MainStatusColor = util.RED
		}
		return false
	}

	a.State.ResetUI()

	if kept {
		a.State.Kept = true
		a.State.MainStatus = "The input file was modified. Please be careful"
		a.State.MainStatusColor = util.YELLOW
	} else {
		a.State.MainStatus = "Completed"
		a.State.MainStatusColor = util.GREEN
	}

	if shouldDelete && !kept {
		var deleteError bool
		if recombine {
			for i := 0; ; i++ {
				chunkPath := inputFile + "." + strconv.Itoa(i)
				if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
					break
				}
				if err := os.Remove(chunkPath); err != nil {
					deleteError = true
				}
			}
		} else {
			if err := os.Remove(inputFile); err != nil {
				deleteError = true
			}
		}
		if deleteError {
			a.State.MainStatus = "Completed (volume couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// resetUI clears UI state but preserves progress flags.
func (a *App) resetUI() {
	a.State.ResetUI()
	if a.passwordEntry != nil {
		a.passwordEntry.SetText("")
	}
	if a.cPasswordEntry != nil {
		a.cPasswordEntry.SetText("")
	}
	if a.commentsEntry != nil {
		a.commentsEntry.SetText("")
	}
	a.updateAdvancedSection()
	a.updatePasswordStrength()
	a.updateValidation()
	a.updateUIState()
}

// showProgressModal shows the progress dialog.
func (a *App) showProgressModal() {
	a.progressBar = widget.NewProgressBar()
	a.progressBar.Min = 0
	a.progressBar.Max = 1

	a.progressLabel = widget.NewLabel("")
	a.progressStatus = widget.NewLabel("")

	a.cancelButton = widget.NewButton("Cancel", func() {
		a.State.Working = false
		a.State.CanCancel = false
		a.cancelled.Store(true)
		a.State.MainStatus = "Operation cancelled by user"
		a.State.MainStatusColor = util.WHITE
		if a.cancelButton != nil {
			a.cancelButton.Disable()
		}
	})

	progressContent := container.NewVBox(
		container.NewBorder(nil, nil, nil, a.cancelButton, a.progressBar),
		a.progressLabel,
		a.progressStatus,
	)

	a.progressModal = dialog.NewCustomWithoutButtons("Progress:", progressContent, a.Window)
	a.progressModal.Show()
}

// showPassgenModal shows the password generator dialog.
func (a *App) showPassgenModal() {
	lengthLabel := widget.NewLabel(fmt.Sprintf("Length: %d", a.State.PassgenLength))

	lengthSlider := widget.NewSlider(12, 64)
	lengthSlider.Value = float64(a.State.PassgenLength)
	lengthSlider.Step = 1
	lengthSlider.OnChanged = func(value float64) {
		a.State.PassgenLength = int32(value)
		lengthLabel.SetText(fmt.Sprintf("Length: %d", int(value)))
	}

	upperCheck := widget.NewCheck("Uppercase", func(checked bool) {
		a.State.PassgenUpper = checked
	})
	upperCheck.SetChecked(a.State.PassgenUpper)

	lowerCheck := widget.NewCheck("Lowercase", func(checked bool) {
		a.State.PassgenLower = checked
	})
	lowerCheck.SetChecked(a.State.PassgenLower)

	numsCheck := widget.NewCheck("Numbers", func(checked bool) {
		a.State.PassgenNums = checked
	})
	numsCheck.SetChecked(a.State.PassgenNums)

	symbolsCheck := widget.NewCheck("Symbols", func(checked bool) {
		a.State.PassgenSymbols = checked
	})
	symbolsCheck.SetChecked(a.State.PassgenSymbols)

	copyCheck := widget.NewCheck("Copy to clipboard", func(checked bool) {
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

	a.passgenModal = dialog.NewCustomConfirm("Generate password:", "Generate", "Cancel", content, func(generate bool) {
		if generate {
			// Check if at least one character type is selected
			if !a.State.PassgenUpper && !a.State.PassgenLower && !a.State.PassgenNums && !a.State.PassgenSymbols {
				return
			}
			password := a.State.GenPassword()
			a.State.Password = password
			a.State.CPassword = password
			a.passwordEntry.SetText(password)
			a.cPasswordEntry.SetText(password)
			a.updatePasswordStrength()
			a.updateValidation()
		}
		a.State.ShowPassgen = false
	}, a.Window)
	a.State.ShowPassgen = true
	a.State.ModalID++
	a.passgenModal.Show()
}

// keyfileListContainer holds the dynamic list of keyfiles in the modal.
var keyfileListContainer *fyne.Container
var keyfileSeparator *widget.Separator
var keyfileOrderCheck *widget.Check

// showKeyfileModal shows the keyfile manager dialog.
func (a *App) showKeyfileModal() {
	// Create order checkbox/label based on mode
	var orderWidget fyne.CanvasObject
	if a.State.Mode != "decrypt" {
		keyfileOrderCheck = widget.NewCheck("Require correct order", func(checked bool) {
			a.State.KeyfileOrdered = checked
		})
		keyfileOrderCheck.SetChecked(a.State.KeyfileOrdered)
		orderWidget = keyfileOrderCheck
	} else if a.State.KeyfileOrdered {
		orderWidget = widget.NewLabel("Correct ordering is required")
	} else {
		orderWidget = widget.NewLabel("") // Empty placeholder
	}

	// Separator (only visible when keyfiles exist)
	keyfileSeparator = widget.NewSeparator()

	// Container for keyfile labels (dynamic)
	keyfileListContainer = container.NewVBox()
	a.updateKeyfileList()

	// Buttons
	clearBtn := widget.NewButton("Clear", func() {
		a.State.Keyfiles = nil
		if a.State.Keyfile {
			a.State.KeyfileLabel = "Keyfiles required"
		} else {
			a.State.KeyfileLabel = "None selected"
		}
		a.State.ModalID++
		a.updateKeyfileList()
		a.updateUIState()
	})

	doneBtn := widget.NewButton("Done", func() {
		a.keyfileModal.Hide()
		a.State.ShowKeyfile = false
		a.updateUIState()
	})
	doneBtn.Importance = widget.HighImportance

	buttonRow := container.NewGridWithColumns(2, clearBtn, doneBtn)

	content := container.NewVBox(
		widget.NewLabel("Drag and drop your keyfiles here"),
		orderWidget,
		keyfileSeparator,
		keyfileListContainer,
		buttonRow,
	)

	a.keyfileModal = dialog.NewCustomWithoutButtons("Manage keyfiles:", content, a.Window)
	a.State.ShowKeyfile = true
	a.State.ModalID++
	a.keyfileModal.Show()
}

// updateKeyfileList updates the keyfile list in the modal.
func (a *App) updateKeyfileList() {
	if keyfileListContainer == nil {
		return
	}

	// Clear existing items
	keyfileListContainer.RemoveAll()

	// Show/hide separator based on keyfile count
	if keyfileSeparator != nil {
		if len(a.State.Keyfiles) > 0 {
			keyfileSeparator.Show()
		} else {
			keyfileSeparator.Hide()
		}
	}

	// Add label for each keyfile
	for _, kf := range a.State.Keyfiles {
		label := widget.NewLabel(filepath.Base(kf))
		keyfileListContainer.Add(label)
	}

	keyfileListContainer.Refresh()
}

// showOverwriteModal shows the overwrite confirmation dialog.
func (a *App) showOverwriteModal() {
	a.overwriteModal = dialog.NewConfirm("Warning:", "Output already exists. Overwrite?", func(overwrite bool) {
		a.State.ShowOverwrite = false
		if overwrite {
			a.startWork()
		}
	}, a.Window)
	a.State.ShowOverwrite = true
	a.State.ModalID++
	a.overwriteModal.Show()
}
