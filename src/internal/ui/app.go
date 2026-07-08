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
//
// Code organization:
//   - app.go: Core UI setup, main layout, state updates
//   - password_section.go: Password input and strength indicator
//   - keyfile_section.go: Keyfile management
//   - advanced_section.go: Encrypt/decrypt options
//   - dialogs.go: Modal dialogs (passgen, progress, overwrite)
//   - operations.go: Encryption/decryption operations
//   - widgets.go: Custom Fyne widgets
//   - drop.go: Drag-and-drop handling
//   - mobile.go: Mobile-specific UI
//   - theme.go: Custom theme
package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/util"
	"context"
	_ "embed"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	fyneApp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	fynetooltip "github.com/dweymouth/fyne-tooltip"
	ttwidget "github.com/dweymouth/fyne-tooltip/widget"
)

//go:embed key.png
var appIconData []byte

// UI dimensions matching original giu implementation
const (
	windowWidth         = 340
	windowHeightEncrypt = 510 // Full height for encrypt mode (more options)
	windowHeightDecrypt = 430 // Reduced height for decrypt mode (fewer options)
	windowHeightInitial = 350 // Compact height for initial state (no advanced options)
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

	// macOS opened-path readiness session. It is used for Finder/Dock-opened
	// paths that may point at iCloud placeholders. It is separate from the global
	// AppleEvent buffer in macos_open.go.
	openReadinessMu            sync.Mutex
	openReadinessGeneration    uint64
	openReadinessCancel        context.CancelFunc
	openReadinessPaths         []string
	openReadinessCollectLate   bool
	openReadinessLastAppend    time.Time
	openReadinessSuppressUntil time.Time
	openReadinessAppliedPaths  []string
	openReadinessAppliedAt     time.Time

	// UI widgets that need to be updated
	inputLabel        *widget.Label
	clearButton       *widget.Button
	aboutButton       *widget.Button
	aboutVersionLabel *widget.Label
	mainContent       *fyne.Container
	passwordEntry     *PasswordEntry
	cPasswordEntry    *PasswordEntry
	strengthIndicator *PasswordStrengthIndicator
	validIndicator    *ValidationIndicator
	keyfileLabel      *widget.Label
	commentsLabel     *widget.Label
	commentsEntry     *widget.Entry
	advancedLabel     *widget.Label
	advancedContainer *fyne.Container
	outputEntry       interface{ SetText(string) }
	startButton       *widget.Button
	statusLabel       *ColoredLabel

	// Confirm password section (hidden in decrypt mode)
	confirmLabel *widget.Label
	confirmRow   *fyne.Container

	// Advisory shown in encrypt mode when the password contains non-ASCII
	// characters (#19): normalized for cross-platform decryption, but the user
	// should be able to reproduce the same characters on other devices.
	nonASCIIHint *widget.Label

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
	paranoidCheck    *ttwidget.Check
	compressCheck    *ttwidget.Check
	reedSolomonCheck *ttwidget.Check
	deleteCheck      *ttwidget.Check
	deniabilityCheck *ttwidget.Check
	recursivelyCheck *ttwidget.Check
	splitCheck       *ttwidget.Check
	splitSizeEntry   *widget.Entry
	splitUnitSelect  *ttwidget.Select

	// Advanced options (decrypt mode)
	forceDecryptCheck *ttwidget.Check
	verifyFirstCheck  *ttwidget.Check
	deleteVolumeCheck *ttwidget.Check
	autoUnzipCheck    *ttwidget.Check
	sameLevelCheck    *ttwidget.Check

	// Modals
	passgenModal   dialog.Dialog
	keyfileModal   dialog.Dialog
	overwriteModal dialog.Dialog
	progressModal  dialog.Dialog
	aboutModal     dialog.Dialog

	// Keyfile modal widgets (moved from package-level to avoid global state)
	keyfileListContainer *fyne.Container
	keyfileSeparator     *widget.Separator
	keyfileOrderCheck    *widget.Check

	// Progress widgets
	progressBar    *widget.ProgressBar
	progressStatus *widget.Label
	cancelButton   *widget.Button

	// Data bindings for reactive UI updates
	boundProgress binding.Float  // Progress bar value (0.0-1.0)
	boundStatus   binding.String // Status text (e.g., "Encrypting at 100 MiB/s")
}

// NewApp creates a new UI application.
func NewApp(version string) (*App, error) {
	// NewState builds the Reed-Solomon codecs once and returns an error on
	// RS-init failure (APP-01). Reuse those codecs here instead of constructing
	// a second, redundant set.
	state, err := app.NewState()
	if err != nil {
		return nil, fmt.Errorf("init app state: %w", err)
	}
	if err := loadTranslations(); err != nil {
		return nil, fmt.Errorf("load translations: %w", err)
	}

	return &App{
		Version:  version,
		State:    state,
		rsCodecs: state.RSCodecs,
		DPI:      1.0,
		// Initialize data bindings
		boundProgress: binding.NewFloat(),
		boundStatus:   binding.NewString(),
	}, nil
}

// Run starts the UI application and optionally loads files passed at startup.
func (a *App) Run(startupPaths []string) {
	// Create Fyne app with unique ID for preferences API support
	a.fyneApp = fyneApp.NewWithID(runtimeAppID())

	// Clean up any leftover temp files from previous sessions (mobile only)
	// Must be called AFTER Fyne app is initialized (isMobile() requires it)
	if isMobile() {
		a.CleanupMobileTempFiles()
	}

	// Apply compact theme to match original Picocrypt look
	a.fyneApp.Settings().SetTheme(NewCompactTheme())

	// Set application icon (embedded PNG)
	appIcon := fyne.NewStaticResource("key.png", appIconData)
	a.fyneApp.SetIcon(appIcon)

	// Create main window. The title intentionally carries no version (#133):
	// taskbars/docks show the .desktop Name or WM_CLASS, and mixing in the
	// version made the user-visible name inconsistent across DEs. The version
	// stays available via the CLI and the packaged file metadata.
	a.Window = a.fyneApp.NewWindow("Picocrypt NG")
	// NewWindow initializes the GLFW driver; native window creation happens on Show.
	prepareWindowIdentity()
	a.Window.SetIcon(appIcon)

	// On desktop: fixed size window; on mobile: flexible size
	if !isMobile() {
		a.Window.SetFixedSize(true)
		a.Window.Resize(fyne.NewSize(windowWidth, windowHeightEncrypt))
	}

	// Set clipboard callback for state
	// Must use fyne.Do() since this may be called from goroutines (e.g., GenPassword)
	a.State.SetClipboard = func(text string) {
		fyne.Do(func() {
			a.fyneApp.Clipboard().SetContent(text)
		})
	}

	// Set close callback to prevent closing during operations
	a.Window.SetCloseIntercept(func() {
		snap := a.State.UISnapshot()
		if !snap.Working && !snap.ShowProgress {
			if !isMobile() {
				fynetooltip.DestroyWindowToolTipLayer(a.Window.Canvas())
			}
			a.Window.Close()
		}
	})

	// Build UI - use mobile layout on mobile devices
	var content fyne.CanvasObject
	if isMobile() {
		content = a.buildMobileUI()
	} else {
		content = a.buildUI()

		// Set up drag and drop (desktop only)
		a.Window.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
			paths := make([]string, len(uris))
			for i, uri := range uris {
				paths[i] = uri.Path()
			}
			a.cancelOpenedPathReadiness()
			a.onDrop(paths)
		})
	}

	// Set up Enter key handler
	if deskCanvas, ok := a.Window.Canvas().(desktop.Canvas); ok {
		deskCanvas.SetOnKeyDown(func(event *fyne.KeyEvent) {
			if event.Name == fyne.KeyReturn || event.Name == fyne.KeyEnter {
				a.onClickStart()
			}
		})
	}

	a.scheduleStartupPaths(startupPaths)

	if !isMobile() {
		content = fynetooltip.AddWindowToolTipLayer(content, a.Window.Canvas())
	}
	a.Window.SetContent(content)
	a.resizeDesktopWindowForContent(content, preferredDesktopWindowHeight(a.State.Mode))
	a.Window.ShowAndRun()
}

func (a *App) scheduleStartupPaths(startupPaths []string) {
	// applyOpened drains paths buffered by the macOS open-file bridge and feeds
	// them through the normal drop handler. It is the notify handler for cold and
	// warm openURLs events after the bridge debounce window goes idle.
	applyOpened := func() {
		fyne.Do(func() {
			opened := drainOpenedPaths()
			if len(opened) == 0 {
				return
			}
			a.applyOpenedPaths(opened)
		})
	}

	// Always wire SetOnStarted: even if startupPaths is empty, AppleEvent paths
	// from a Finder cold launch may have been buffered by the cgo handler before
	// Go's main() ran (drainOpenedPaths returns nothing on non-darwin).
	a.fyneApp.Lifecycle().SetOnStarted(func() {
		// Register the notify handler before checking for cold-launch AppleEvent
		// batches so Finder/Dock opens use the same debounce window as warm opens.
		setOpenedPathsNotify(applyOpened)
		if hasOpenedPaths() {
			flushOpenedPaths()
		}
		if len(startupPaths) > 0 {
			fyne.Do(func() {
				a.applyStartupPaths(startupPaths)
			})
		}
	})
}

// showFileDialogWithResize temporarily resizes the window to accommodate file dialogs.
// This is necessary because Fyne file dialogs are constrained by the parent window size
// when using fixed-size windows. The window is restored after the dialog closes.
func (a *App) showFileDialogWithResize(d dialog.Dialog, dialogSize fyne.Size) {
	// Skip resize handling on mobile - windows are flexible there
	if isMobile() {
		d.Resize(dialogSize)
		d.Show()
		return
	}

	// Calculate current window size to restore later
	originalHeight := preferredDesktopWindowHeight(a.State.Mode)

	// Temporarily allow window resizing and make room for dialog
	a.Window.SetFixedSize(false)
	a.Window.Resize(fyne.NewSize(dialogSize.Width+50, dialogSize.Height+50))

	d.SetOnClosed(func() {
		a.resizeDesktopWindowForCurrentContent(originalHeight)
		a.Window.SetFixedSize(true)
	})

	d.Resize(dialogSize)
	d.Show()
}

// fixedWidthLayout is a layout that forces a fixed width (used in tests).
//
//nolint:unused // used by widgets_test.go
type fixedWidthLayout struct {
	width float32
}

//nolint:unused // used by widgets_test.go
func (f *fixedWidthLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(f.width, 0)
	}
	min := objects[0].MinSize()
	return fyne.NewSize(f.width, min.Height)
}

//nolint:unused // used by widgets_test.go
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
	a.clearButton = widget.NewButton("Clear", func() {
		a.cancelOpenedPathReadiness()
		a.resetUI()
	})
	// MediumImportance gives the button a visible border
	a.clearButton.Importance = widget.MediumImportance

	// Icon-only About button: keeps the fixed-size window unchanged while
	// giving the GUI a version indicator (the title carries none, #133).
	a.aboutButton = widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		a.showAboutModal()
	})
	a.aboutButton.Importance = widget.LowImportance

	headerRow := container.NewBorder(nil, nil, a.aboutButton, a.clearButton, a.inputLabel)

	// Password section (from password_section.go)
	passwordSection := a.buildPasswordSection()

	// Keyfiles section (from keyfile_section.go)
	keyfilesSection := a.buildKeyfilesSection()

	// Comments section
	commentsSection := a.buildCommentsSection()

	// Advanced section (from advanced_section.go)
	a.advancedContainer = container.NewVBox()
	a.updateAdvancedSection()

	// Output section
	outputSection := a.buildOutputSection()

	// Start button and status
	a.startButton = widget.NewButton(a.State.StartLabel, a.onClickStart)
	a.startButton.Importance = widget.HighImportance

	a.statusLabel = NewColoredLabel(a.State.MainStatus, a.State.MainStatusColor)

	// Advanced section label (hidden when no mode selected)
	a.advancedLabel = widget.NewLabel("Advanced:")
	a.advancedLabel.TextStyle = fyne.TextStyle{Bold: true}
	a.advancedLabel.Hide() // Initially hidden until files are dropped

	// Main content container
	a.mainContent = container.NewVBox(
		passwordSection,
		keyfilesSection,
		widget.NewSeparator(),
		commentsSection,
		a.advancedLabel,
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

func preferredDesktopWindowHeight(mode string) float32 {
	switch mode {
	case "encrypt":
		return windowHeightEncrypt
	case "decrypt":
		return windowHeightDecrypt
	default:
		return windowHeightInitial
	}
}

func (a *App) resizeDesktopWindowForCurrentContent(preferredHeight float32) {
	var content fyne.CanvasObject
	if a.Window != nil {
		content = a.Window.Content()
	}
	a.resizeDesktopWindowForContent(content, preferredHeight)
}

func (a *App) resizeDesktopWindowForContent(content fyne.CanvasObject, preferredHeight float32) {
	if isMobile() || a.Window == nil {
		return
	}
	size := fyne.NewSize(windowWidth, preferredHeight)
	if content != nil {
		size = size.Max(content.MinSize())
	}
	a.Window.Resize(size)
}

// buildCommentsSection creates the comments input section.
func (a *App) buildCommentsSection() fyne.CanvasObject {
	a.commentsLabel = widget.NewLabel(a.State.CommentsLabel)
	a.commentsLabel.TextStyle = fyne.TextStyle{Bold: true}

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
	outputEntry := NewDisabledEntry()
	a.outputEntry = outputEntry

	a.changeBtn = widget.NewButton("Change", func() {
		a.changeOutputFile()
	})

	row := container.NewBorder(nil, nil, nil, a.changeBtn, outputEntry)

	// Create bold label for better visual hierarchy
	outputLabel := widget.NewLabel("Save output as:")
	outputLabel.TextStyle = fyne.TextStyle{Bold: true}

	return container.NewVBox(
		outputLabel,
		row,
	)
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
	snap := a.State.UISnapshot()
	hasFiles := snap.AllFileCount > 0 || snap.OnlyFileCount > 0 || snap.OnlyFolderCount > 0
	isScanning := snap.Scanning

	// Main content disabled - matches giu: (len(allFiles) == 0 && len(onlyFiles) == 0) || scanning
	// Note: we also check onlyFolders for consistency
	mainDisabled := !hasFiles || isScanning

	// Clear button
	if a.clearButton != nil {
		if mainDisabled {
			a.clearButton.Disable()
		} else {
			a.clearButton.Enable()
		}
	}

	// Password section state (from password_section.go)
	a.updatePasswordUIState(mainDisabled, snap)

	// Keyfile section state (from keyfile_section.go)
	a.updateKeyfileUIState(mainDisabled, snap)

	// Comments section - complex nested logic
	commentsOuterDisabled := (snap.Mode != "decrypt" &&
		((snap.KeyfileCount == 0 && snap.Password == "") ||
			(snap.Password != snap.CPassword))) ||
		snap.Deniability
	commentsInnerDisabled := snap.Mode == "decrypt" &&
		(snap.Comments == "" || snap.Comments == "Comments are corrupted")

	if a.commentsEntry != nil {
		// In decrypt mode with valid comments, keep entry enabled but read-only
		// (OnChanged will prevent actual changes). This keeps text visible, not pale.
		if snap.Mode == "decrypt" && snap.Comments != "" && snap.Comments != "Comments are corrupted" {
			a.commentsEntry.Enable() // Keep text visible (not pale)
		} else if mainDisabled || commentsOuterDisabled || commentsInnerDisabled || snap.CommentsDisabled {
			a.commentsEntry.Disable()
		} else {
			a.commentsEntry.Enable()
		}
	}

	// Advanced section and Start button
	advancedAndStartDisabled := !snap.CanStart()

	// Update advanced section checkboxes/inputs (from advanced_section.go)
	a.updateAdvancedDisableStateFromSnapshot(snap)

	// Start button - MUST be disabled when no credentials or passwords don't match
	if a.startButton != nil {
		label := snap.StartLabel
		if snap.Recursively {
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
		if snap.OutputFile != "" {
			outputDisplay = filepath.Base(snap.OutputFile)
			if snap.Split {
				outputDisplay += ".*"
			}
			if snap.Recursively {
				outputDisplay = "(multiple values)"
			}
		}
		a.outputEntry.SetText(outputDisplay)
	}

	// Change button - disabled when recursively
	if a.changeBtn != nil {
		if mainDisabled || advancedAndStartDisabled || snap.Recursively {
			a.changeBtn.Disable()
		} else {
			a.changeBtn.Enable()
		}
	}

	// Update status
	if a.statusLabel != nil {
		statusText := snap.MainStatus
		if snap.MainStatus == "Ready" && snap.RequiredFreeSpace > 0 {
			multiplier := 1
			if snap.AllFileCount > 1 || snap.OnlyFolderCount > 0 {
				multiplier++
			}
			if snap.Deniability {
				multiplier++
			}
			if snap.Split {
				multiplier++
			}
			if snap.Recombine {
				multiplier++
			}
			if snap.AutoUnzip {
				multiplier++
			}
			statusText = "Ready (ensure >" + util.Sizeify(snap.RequiredFreeSpace*int64(multiplier)) + " free)"
		}
		a.statusLabel.SetText(statusText)
		a.statusLabel.SetColor(snap.MainStatusColor)
	}

	// Update labels
	if a.inputLabel != nil {
		a.inputLabel.SetText(snap.InputLabel)
	}

	if a.keyfileLabel != nil {
		a.keyfileLabel.SetText(snap.KeyfileLabel)
	}

	if a.commentsLabel != nil {
		a.commentsLabel.SetText(snap.CommentsLabel)
	}
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
