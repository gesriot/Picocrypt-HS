// Package ui provides the Picocrypt NG graphical user interface using giu (Dear ImGui wrapper).
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
	"fmt"
	"image"
	"image/color"
	"math"
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

	"github.com/Picocrypt/dialog"
	"github.com/Picocrypt/giu"
	"github.com/Picocrypt/zxcvbn-go"
)

// App represents the main UI application.
type App struct {
	Window  *giu.MasterWindow
	Version string
	DPI     float32

	// Application state
	State *app.State

	// Reed-Solomon codecs
	rsCodecs *encoding.RSCodecs

	// Cancellation flag (atomic for thread safety across goroutines)
	cancelled atomic.Bool
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
	}, nil
}

// Run starts the UI application.
func (a *App) Run() {
	a.Window = giu.NewMasterWindow(
		"Picocrypt NG "+a.Version[1:],
		318, 507,
		giu.MasterWindowFlagsNotResizable,
	)

	dialog.Init()

	a.Window.SetDropCallback(a.onDrop)
	a.Window.SetCloseCallback(func() bool {
		return !a.State.Working && !a.State.ShowProgress
	})

	a.DPI = giu.Context.GetPlatform().GetContentScale()
	a.State.DPI = a.DPI
	a.State.Window = a.Window

	a.Window.Run(a.draw)
}

// CreateReporter creates a UIReporter for progress updates.
func (a *App) CreateReporter() *app.UIReporter {
	return app.NewUIReporter(
		func(text string) {
			a.State.PopupStatus = text
			giu.Update()
		},
		func(fraction float32, info string) {
			a.State.Progress = fraction
			a.State.ProgressInfo = info
			giu.Update()
		},
		func(can bool) {
			a.State.CanCancel = can
			giu.Update()
		},
		func() {
			giu.Update()
		},
		func() bool {
			return !a.State.Working
		},
	)
}

// draw is the main render function - matches original layout exactly.
func (a *App) draw() {
	giu.SingleWindow().Flags(524351).Layout(
		giu.Custom(func() {
			// Handle Enter key
			if giu.IsKeyReleased(giu.KeyEnter) {
				a.onClickStart()
				return
			}

			// Render popup modals
			a.drawPassgenModal()
			a.drawKeyfileModal()
			a.drawOverwriteModal()
			a.drawProgressModal()
		}),

		// Input label with Clear button
		giu.Row(
			giu.Label(a.State.InputLabel),
			giu.Custom(func() {
				bw, _ := giu.CalcTextSize("Clear")
				p, _ := giu.GetWindowPadding()
				bw += p * 2
				giu.Dummy((bw+p)/-a.DPI, 0).Build()
				giu.SameLine()
				giu.Style().SetDisabled(
					(len(a.State.AllFiles) == 0 && len(a.State.OnlyFiles) == 0) || a.State.Scanning,
				).To(
					giu.Button("Clear").Size(bw/a.DPI, 0).OnClick(a.resetUI),
					giu.Tooltip("Clear all input files and reset UI state"),
				).Build()
			}),
		),

		giu.Separator(),

		// Main content - disabled when no files
		giu.Style().SetDisabled(
			(len(a.State.AllFiles) == 0 && len(a.State.OnlyFiles) == 0) || a.State.Scanning,
		).To(
			// Password label
			giu.Label("Password:"),

			// Password buttons row
			giu.Row(
				giu.Button(a.State.PasswordStateLabel).Size(54, 0).OnClick(func() {
					if a.State.PasswordState == giu.InputTextFlagsPassword {
						a.State.PasswordState = giu.InputTextFlagsNone
						a.State.PasswordStateLabel = "Hide"
					} else {
						a.State.PasswordState = giu.InputTextFlagsPassword
						a.State.PasswordStateLabel = "Show"
					}
					giu.Update()
				}),
				giu.Tooltip("Toggle the visibility of password entries"),

				giu.Button("Clear").Size(54, 0).OnClick(func() {
					a.State.Password = ""
					a.State.CPassword = ""
					giu.Update()
				}),
				giu.Tooltip("Clear the password entries"),

				giu.Button("Copy").Size(54, 0).OnClick(func() {
					giu.Context.GetPlatform().SetClipboard(a.State.Password)
					giu.Update()
				}),
				giu.Tooltip("Copy the password into your clipboard"),

				giu.Button("Paste").Size(54, 0).OnClick(func() {
					tmp := giu.Context.GetPlatform().GetClipboard()
					a.State.Password = tmp
					if a.State.Mode != "decrypt" {
						a.State.CPassword = tmp
					}
					a.State.PasswordStrength = zxcvbn.PasswordStrength(a.State.Password, nil).Score
					giu.Update()
				}),
				giu.Tooltip("Paste a password from your clipboard"),

				giu.Style().SetDisabled(a.State.Mode == "decrypt").To(
					giu.Button("Create").Size(54, 0).OnClick(func() {
						a.State.ShowPassgen = true
						a.State.ModalID++
						giu.Update()
					}),
				),
				giu.Tooltip("Generate a cryptographically secure password"),
			),

			// Password input with strength indicator
			giu.Row(
				giu.InputText(&a.State.Password).Flags(a.State.PasswordState).Size(302/a.DPI).OnChange(func() {
					a.State.PasswordStrength = zxcvbn.PasswordStrength(a.State.Password, nil).Score
					giu.Update()
				}),
				giu.Custom(func() {
					c := giu.GetCanvas()
					p := giu.GetCursorScreenPos()
					col := color.RGBA{
						uint8(0xc8 - 31*a.State.PasswordStrength),
						uint8(0x4c + 31*a.State.PasswordStrength), 0x4b, 0xff,
					}
					if a.State.Password == "" || a.State.Mode == "decrypt" {
						col = util.TRANSPARENT
					}
					path := p.Add(image.Pt(
						int(math.Round(-20*float64(a.DPI))),
						int(math.Round(12*float64(a.DPI))),
					))
					c.PathArcTo(path, 6*a.DPI, -math.Pi/2, math.Pi*(.4*float32(a.State.PasswordStrength)-.1), -1)
					c.PathStroke(col, false, 2)
				}),
			),

			giu.Dummy(0, 0),

			// Confirm password (disabled in decrypt mode or when no password)
			giu.Style().SetDisabled(a.State.Password == "" || a.State.Mode == "decrypt").To(
				giu.Label("Confirm password:"),
				giu.Row(
					giu.InputText(&a.State.CPassword).Flags(a.State.PasswordState).Size(302/a.DPI),
					giu.Custom(func() {
						c := giu.GetCanvas()
						p := giu.GetCursorScreenPos()
						col := color.RGBA{0x4c, 0xc8, 0x4b, 0xff}
						if a.State.CPassword != a.State.Password {
							col = color.RGBA{0xc8, 0x4c, 0x4b, 0xff}
						}
						if a.State.Password == "" || a.State.CPassword == "" || a.State.Mode == "decrypt" {
							col = util.TRANSPARENT
						}
						path := p.Add(image.Pt(
							int(math.Round(-20*float64(a.DPI))),
							int(math.Round(12*float64(a.DPI))),
						))
						c.PathArcTo(path, 6*a.DPI, 0, 2*math.Pi, -1)
						c.PathStroke(col, false, 2)
					}),
				),
			),

			giu.Dummy(0, 0),

			// Keyfiles row
			giu.Style().SetDisabled(a.State.Mode == "decrypt" && !a.State.Keyfile && !a.State.Deniability).To(
				giu.Row(
					giu.Label("Keyfiles:"),
					giu.Button("Edit").Size(54, 0).OnClick(func() {
						a.State.ShowKeyfile = true
						a.State.ModalID++
						giu.Update()
					}),
					giu.Tooltip("Manage keyfiles to use for "+func() string {
						if a.State.Mode != "decrypt" {
							return "encryption"
						}
						return "decryption"
					}()),

					giu.Style().SetDisabled(a.State.Mode == "decrypt").To(
						giu.Button("Create").Size(54, 0).OnClick(func() {
							a.createKeyfile()
						}),
						giu.Tooltip("Generate a cryptographically secure keyfile"),
					),
					giu.Style().SetDisabled(true).To(
						giu.InputText(&a.State.KeyfileLabel).Size(giu.Auto),
					),
				),
			),
		),

		giu.Separator(),

		// Comments and Advanced section - complex disable logic
		giu.Style().SetDisabled(
			a.State.Mode != "decrypt" &&
				((len(a.State.Keyfiles) == 0 && a.State.Password == "") ||
					(a.State.Password != a.State.CPassword)) ||
				a.State.Deniability,
		).To(
			// Comments
			giu.Style().SetDisabled(
				a.State.Mode == "decrypt" && (a.State.Comments == "" || a.State.Comments == "Comments are corrupted"),
			).To(
				giu.Label(a.State.CommentsLabel),
				giu.InputText(&a.State.Comments).Size(giu.Auto).Flags(func() giu.InputTextFlags {
					if a.State.CommentsDisabled {
						return giu.InputTextFlagsReadOnly
					} else if a.State.Deniability {
						a.State.Comments = ""
					}
					return giu.InputTextFlagsNone
				}()),
				giu.Custom(func() {
					if !a.State.CommentsDisabled {
						giu.Tooltip("Note: comments are not encrypted!").Build()
					}
				}),
			),
		),

		// Advanced options
		giu.Style().SetDisabled(
			(len(a.State.Keyfiles) == 0 && a.State.Password == "") ||
				(a.State.Mode == "encrypt" && a.State.Password != a.State.CPassword),
		).To(
			giu.Label("Advanced:"),
			giu.Custom(func() {
				if a.State.Mode != "decrypt" {
					// Show encrypt options by default (when mode is "" or "encrypt")
					a.drawEncryptOptions()
				} else {
					// Show decrypt options only when mode is "decrypt"
					a.drawDecryptOptions()
				}
			}),

			// Save output as
			giu.Style().SetDisabled(a.State.Recursively).To(
				giu.Label("Save output as:"),
				giu.Custom(func() {
					w, _ := giu.GetAvailableRegion()
					bw, _ := giu.CalcTextSize("Change")
					p, _ := giu.GetWindowPadding()
					bw += p * 2
					dw := w - bw - p

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

					giu.Style().SetDisabled(true).To(
						giu.InputText(&outputDisplay).Size(dw / a.DPI / a.DPI).Flags(16384),
					).Build()

					giu.SameLine()
					giu.Button("Change").Size(bw/a.DPI, 0).OnClick(func() {
						a.changeOutputFile()
					}).Build()
					giu.Tooltip("Save the output with a custom name and path").Build()
				}),
			),

			giu.Dummy(0, 0),
			giu.Separator(),
			giu.Dummy(0, 0),

			// Start button
			giu.Button(func() string {
				if !a.State.Recursively {
					return a.State.StartLabel
				}
				return "Process"
			}()).Size(giu.Auto, 34).OnClick(a.onClickStart),

			// Status display
			giu.Custom(func() {
				if a.State.MainStatus != "Ready" {
					giu.Style().SetColor(giu.StyleColorText, a.State.MainStatusColor).To(
						giu.Label(a.State.MainStatus),
					).Build()
					return
				}
				if a.State.RequiredFreeSpace > 0 {
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
					giu.Style().SetColor(giu.StyleColorText, util.WHITE).To(
						giu.Label("Ready (ensure >" + util.Sizeify(a.State.RequiredFreeSpace*int64(multiplier)) + " of disk space is free)"),
					).Build()
				} else {
					giu.Style().SetColor(giu.StyleColorText, util.WHITE).To(
						giu.Label("Ready"),
					).Build()
				}
			}),
		),

		// Auto-resize window
		giu.Custom(func() {
			a.Window.SetSize(int(318*a.DPI), giu.GetCursorPos().Y+1)
		}),
	)
}

// drawEncryptOptions renders encrypt mode options (matches original exactly).
func (a *App) drawEncryptOptions() {
	// Row 1: Paranoid + Compress
	giu.Row(
		giu.Checkbox("Paranoid mode", &a.State.Paranoid),
		giu.Tooltip("Provides the highest level of security attainable"),
		giu.Dummy(-170, 0),
		giu.Style().SetDisabled(
			a.State.Recursively || (len(a.State.AllFiles) <= 1 && len(a.State.OnlyFolders) == 0),
		).To(
			giu.Checkbox("Compress files", &a.State.Compress),
			giu.Tooltip("Compress files with Deflate before encrypting"),
		),
	).Build()

	// Row 2: Reed-Solomon + Delete files
	giu.Row(
		giu.Checkbox("Reed-Solomon", &a.State.ReedSolomon),
		giu.Tooltip("Prevent file corruption with erasure coding"),
		giu.Dummy(-170, 0),
		giu.Checkbox("Delete files", &a.State.Delete),
		giu.Tooltip("Delete the input files after encryption"),
	).Build()

	// Row 3: Deniability + Recursively
	giu.Row(
		giu.Checkbox("Deniability", &a.State.Deniability),
		giu.Tooltip("Warning: only use this if you know what it does!"),
		giu.Dummy(-170, 0),
		giu.Style().SetDisabled(len(a.State.AllFiles) <= 1 && len(a.State.OnlyFolders) == 0).To(
			giu.Checkbox("Recursively", &a.State.Recursively).OnChange(func() {
				a.State.Compress = false
			}),
			giu.Tooltip("Warning: only use this if you know what it does!"),
		),
	).Build()

	// Row 4: Split into chunks
	giu.Row(
		giu.Checkbox("Split into chunks:", &a.State.Split),
		giu.Tooltip("Split the output file into smaller chunks"),
		giu.Dummy(-170, 0),
		giu.InputText(&a.State.SplitSize).Size(86/a.DPI).Flags(2).OnChange(func() {
			a.State.Split = a.State.SplitSize != ""
		}),
		giu.Tooltip("Choose the chunk size"),
		giu.Combo("##splitter", a.State.SplitUnits[a.State.SplitSelected], a.State.SplitUnits, &a.State.SplitSelected).Size(68),
		giu.Tooltip("Choose the chunk units"),
	).Build()
}

// drawDecryptOptions renders decrypt mode options (matches original exactly).
func (a *App) drawDecryptOptions() {
	// Row 1: Force decrypt + Delete volume
	giu.Row(
		giu.Style().SetDisabled(a.State.Deniability).To(
			giu.Checkbox("Force decrypt", &a.State.Keep),
			giu.Tooltip("Override security measures when decrypting"),
		),
		giu.Dummy(-170, 0),
		giu.Checkbox("Delete volume", &a.State.Delete),
		giu.Tooltip("Delete the volume after a successful decryption"),
	).Build()

	// Row 2: Auto unzip + Same level
	giu.Row(
		giu.Style().SetDisabled(!strings.HasSuffix(a.State.InputFile, ".zip.pcv")).To(
			giu.Checkbox("Auto unzip", &a.State.AutoUnzip).OnChange(func() {
				if !a.State.AutoUnzip {
					a.State.SameLevel = false
				}
			}),
			giu.Tooltip("Extract .zip upon decryption (may overwrite files)"),
		),
		giu.Dummy(-170, 0),
		giu.Style().SetDisabled(!a.State.AutoUnzip).To(
			giu.Checkbox("Same level", &a.State.SameLevel),
			giu.Tooltip("Extract .zip contents to same folder as volume"),
		),
	).Build()
}

// createKeyfile creates a new random keyfile.
func (a *App) createKeyfile() {
	startDir := ""
	if len(a.State.OnlyFiles) > 0 {
		startDir = filepath.Dir(a.State.OnlyFiles[0])
	} else if len(a.State.OnlyFolders) > 0 {
		startDir = filepath.Dir(a.State.OnlyFolders[0])
	}

	f := dialog.File().Title("Choose where to save the keyfile")
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
		giu.Update()
		return
	}

	data := make([]byte, 32)
	if n, err := rand.Read(data); err != nil || n != 32 {
		_ = fout.Close()
		a.State.MainStatus = "Failed to generate keyfile"
		a.State.MainStatusColor = util.RED
		giu.Update()
		return
	}

	n, err := fout.Write(data)
	if err != nil || n != 32 {
		_ = fout.Close()
		a.State.MainStatus = "Failed to write keyfile"
		a.State.MainStatusColor = util.RED
		giu.Update()
		return
	}

	if err := fout.Close(); err != nil {
		a.State.MainStatus = "Failed to close keyfile"
		a.State.MainStatusColor = util.RED
		giu.Update()
		return
	}

	a.State.MainStatus = "Ready"
	a.State.MainStatusColor = util.WHITE
	giu.Update()
}

// changeOutputFile opens a dialog to change the output file path.
func (a *App) changeOutputFile() {
	f := dialog.File().Title("Choose where to save the output. Don't include extensions")

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
	giu.Update()
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
		a.State.ShowOverwrite = true
		a.State.ModalID++
		giu.Update()
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
	giu.Update()

	if !a.State.Recursively {
		// Normal mode: process single file/folder(s)
		go func() {
			a.doWork()
			// Success: status set to "Completed" by doEncrypt/doDecrypt
			// Error: status set to error message by doEncrypt/doDecrypt
			// Cancel: status set to "Operation cancelled by user" by cancel button
			a.State.Working = false
			a.State.ShowProgress = false
			giu.Update()
		}()
	} else {
		// Recursive mode: process each file individually
		// (matches original lines 261-313)
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
// This matches the original "Recursively" checkbox behavior (lines 261-313).
//
// When enabled:
//   - Each file in AllFiles is encrypted/decrypted separately
//   - Same password, keyfiles, and options apply to all files
//   - Each file gets its own .pcv output (input.txt -> input.txt.pcv)
//
// This is different from normal multi-file mode which zips files together.
//
// IMPROVEMENT over original: tracks and reports failed files instead of silently continuing.
func (a *App) startRecursiveWork() {
	// Handle empty file list case
	if len(a.State.AllFiles) == 0 {
		a.State.MainStatus = "No files to process"
		a.State.MainStatusColor = util.YELLOW
		a.State.Working = false
		a.State.ShowProgress = false
		giu.Update()
		return
	}

	// Store all settings before they get cleared by onDrop/resetUI
	// (matches original lines 263-276)
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

	// Copy the file list since it will be modified
	files := make([]string, len(a.State.AllFiles))
	copy(files, a.State.AllFiles)

	go func() {
		var failedCount int
		var successCount int

		for i, file := range files {
			// Update progress info with current file
			a.State.PopupStatus = fmt.Sprintf("Processing file %d/%d...", i+1, len(files))
			giu.Update()

			// Simulate dropping the file (matches original line 280)
			// This sets up inputFile, outputFile, mode, etc.
			// Note: onDrop() calls resetUI() which uses ResetUI() that preserves
			// ShowProgress, Working, CanCancel (matches original behavior)
			a.onDrop([]string{file})

			// Restore all saved settings (matches original lines 282-298)
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
			// Only restore deniability if not decrypting
			// (original line 292-294: deniability is read from header during decrypt)
			if a.State.Mode != "decrypt" {
				a.State.Deniability = savedDeniability
			}
			a.State.Split = savedSplit
			a.State.SplitSize = savedSplitSize
			a.State.SplitSelected = savedSplitSelected
			a.State.Delete = savedDelete

			// Process this file and track result
			if a.doWork() {
				successCount++
			} else {
				failedCount++
			}

			// Check if user cancelled (matches original lines 301-307)
			// Original only checks `if !working` - it continues on errors, only stops on cancel
			// The cancel button sets Working=false and MainStatus="Operation cancelled by user"
			if a.cancelled.Load() {
				// Don't call resetUI() - it would overwrite the cancellation status
				a.State.Working = false
				a.State.ShowProgress = false
				giu.Update()
				return
			}
		}

		// All files processed - report results
		a.State.Working = false
		a.State.ShowProgress = false

		// Set final status based on results
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

		giu.Update()
	}()
}

// doEncrypt performs encryption using the volume package.
// Returns true if encryption completed successfully.
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

	// Save delete preference before reset
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

	// Save files for deletion before reset
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

	// Reset UI after successful completion (like original work() line 2583)
	// Use ResetUI() which preserves ShowProgress, Working, CanCancel
	a.State.ResetUI()

	a.State.MainStatus = "Completed"
	a.State.MainStatusColor = util.GREEN

	// Delete files if requested
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
		// Warn user if some files couldn't be deleted (don't fail the operation)
		if len(deleteErrors) > 0 {
			a.State.MainStatus = "Completed (some files couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// doDecrypt performs decryption using the volume package.
// Returns true if decryption completed successfully.
func (a *App) doDecrypt(reporter *app.UIReporter) bool {
	kept := false

	// Save values before potential reset
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

	// Reset UI after successful completion (like original work() line 2583)
	// Use ResetUI() which preserves ShowProgress, Working, CanCancel
	a.State.ResetUI()

	// Check if file was kept despite errors (force decrypt used)
	if kept {
		a.State.Kept = true
		a.State.MainStatus = "The input file was modified. Please be careful"
		a.State.MainStatusColor = util.YELLOW
	} else {
		a.State.MainStatus = "Completed"
		a.State.MainStatusColor = util.GREEN
	}

	// Delete volume if requested (and not kept)
	if shouldDelete && !kept {
		var deleteError bool
		if recombine {
			// Remove each chunk: file.pcv.0, file.pcv.1, etc. (matches original lines 2525-2536)
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
		// Warn user if volume couldn't be deleted (don't fail the operation)
		if deleteError {
			a.State.MainStatus = "Completed (volume couldn't be deleted)"
			a.State.MainStatusColor = util.YELLOW
		}
	}

	return true
}

// resetUI clears UI state but preserves progress flags (matches original resetUI).
// For full reset including progress state, call a.State.Reset() directly.
func (a *App) resetUI() {
	a.State.ResetUI()
	giu.Update()
}
