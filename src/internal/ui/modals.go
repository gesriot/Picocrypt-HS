package ui

import (
	"os"
	"path/filepath"
	"strconv"

	"Picocrypt-NG/internal/util"

	"github.com/Picocrypt/giu"
	"github.com/Picocrypt/zxcvbn-go"
)

// drawPassgenModal renders the password generator popup (matches original exactly).
func (a *App) drawPassgenModal() {
	if !a.State.ShowPassgen {
		return
	}

	giu.PopupModal("Generate password:##"+strconv.Itoa(a.State.ModalID)).Flags(6).Layout(
		giu.Row(
			giu.Label("Length:"),
			giu.SliderInt(&a.State.PassgenLength, 12, 64).Size(giu.Auto),
		),
		giu.Checkbox("Uppercase", &a.State.PassgenUpper),
		giu.Checkbox("Lowercase", &a.State.PassgenLower),
		giu.Checkbox("Numbers", &a.State.PassgenNums),
		giu.Checkbox("Symbols", &a.State.PassgenSymbols),
		giu.Checkbox("Copy to clipboard", &a.State.PassgenCopy),
		giu.Row(
			giu.Button("Cancel").Size(100, 0).OnClick(func() {
				giu.CloseCurrentPopup()
				a.State.ShowPassgen = false
			}),
			giu.Style().SetDisabled(
				!(a.State.PassgenUpper || a.State.PassgenLower ||
					a.State.PassgenNums || a.State.PassgenSymbols),
			).To(
				giu.Button("Generate").Size(100, 0).OnClick(func() {
					a.State.Password = a.State.GenPassword()
					a.State.CPassword = a.State.Password
					a.State.PasswordStrength = zxcvbn.PasswordStrength(a.State.Password, nil).Score

					giu.CloseCurrentPopup()
					a.State.ShowPassgen = false
				}),
			),
		),
	).Build()

	giu.OpenPopup("Generate password:##" + strconv.Itoa(a.State.ModalID))
	giu.Update()
}

// drawKeyfileModal renders the keyfile manager popup (matches original exactly).
func (a *App) drawKeyfileModal() {
	if !a.State.ShowKeyfile {
		return
	}

	giu.PopupModal("Manage keyfiles:##"+strconv.Itoa(a.State.ModalID)).Flags(70).Layout(
		giu.Label("Drag and drop your keyfiles here"),
		giu.Custom(func() {
			if a.State.Mode != "decrypt" {
				giu.Checkbox("Require correct order", &a.State.KeyfileOrdered).Build()
				giu.Tooltip("Ordering of keyfiles will matter").Build()
			} else if a.State.KeyfileOrdered {
				giu.Label("Correct ordering is required").Build()
			}
		}),
		giu.Custom(func() {
			if len(a.State.Keyfiles) > 0 {
				giu.Separator().Build()
			}
			for _, path := range a.State.Keyfiles {
				giu.Label(filepath.Base(path)).Build()
			}
		}),
		giu.Row(
			giu.Button("Clear").Size(100, 0).OnClick(func() {
				a.State.Keyfiles = nil
				if a.State.Keyfile {
					a.State.KeyfileLabel = "Keyfiles required"
				} else {
					a.State.KeyfileLabel = "None selected"
				}
				a.State.ModalID++
				giu.Update()
			}),
			giu.Tooltip("Remove all keyfiles"),

			giu.Button("Done").Size(100, 0).OnClick(func() {
				giu.CloseCurrentPopup()
				a.State.ShowKeyfile = false
			}),
		),
	).Build()

	giu.OpenPopup("Manage keyfiles:##" + strconv.Itoa(a.State.ModalID))
	giu.Update()
}

// drawOverwriteModal renders the overwrite confirmation popup (matches original exactly).
func (a *App) drawOverwriteModal() {
	if !a.State.ShowOverwrite {
		return
	}

	giu.PopupModal("Warning:##"+strconv.Itoa(a.State.ModalID)).Flags(6).Layout(
		giu.Label("Output already exists. Overwrite?"),
		giu.Row(
			giu.Button("No").Size(100, 0).OnClick(func() {
				giu.CloseCurrentPopup()
				a.State.ShowOverwrite = false
			}),
			giu.Button("Yes").Size(100, 0).OnClick(func() {
				giu.CloseCurrentPopup()
				a.State.ShowOverwrite = false
				a.startWork()
			}),
		),
	).Build()

	giu.OpenPopup("Warning:##" + strconv.Itoa(a.State.ModalID))
	giu.Update()
}

// drawProgressModal renders the progress popup (matches original exactly).
func (a *App) drawProgressModal() {
	if !a.State.ShowProgress {
		return
	}

	giu.PopupModal("Progress:##"+strconv.Itoa(a.State.ModalID)).Flags(6|1<<0).Layout(
		giu.Dummy(0, 0),
		giu.Row(
			giu.ProgressBar(a.State.Progress).Size(210, 0).Overlay(a.State.ProgressInfo),
			giu.Style().SetDisabled(!a.State.CanCancel).To(
				giu.Button(func() string {
					if a.State.Working {
						return "Cancel"
					}
					return "..."
				}()).Size(58, 0).OnClick(func() {
					a.State.Working = false
					a.State.CanCancel = false
					a.cancelled.Store(true)
					// Set cancellation status (matches original line 2630)
					a.State.MainStatus = "Operation cancelled by user"
					a.State.MainStatusColor = util.WHITE
				}),
			),
		),
		giu.Label(a.State.PopupStatus),
	).Build()

	giu.OpenPopup("Progress:##" + strconv.Itoa(a.State.ModalID))
	giu.Update()
}

// handleKeyfileDrop processes dropped keyfiles when the modal is open.
func (a *App) handleKeyfileDrop(paths []string) bool {
	if !a.State.ShowKeyfile {
		return false
	}

	// Add keyfiles, checking for duplicates and access
	for _, path := range paths {
		// Check if duplicate
		duplicate := false
		for _, existing := range a.State.Keyfiles {
			if path == existing {
				duplicate = true
				break
			}
		}

		// Check if accessible and not a directory
		stat, err := os.Stat(path)
		if err != nil {
			a.State.ShowKeyfile = false
			a.resetUI()
			a.State.MainStatus = "Keyfile read access denied"
			a.State.MainStatusColor = util.RED
			giu.Update()
			return true
		}

		if !duplicate && !stat.IsDir() {
			a.State.Keyfiles = append(a.State.Keyfiles, path)
		}
	}

	// Update label
	switch len(a.State.Keyfiles) {
	case 0:
		if a.State.Keyfile {
			a.State.KeyfileLabel = "Keyfiles required"
		} else {
			a.State.KeyfileLabel = "None selected"
		}
	case 1:
		a.State.KeyfileLabel = "Using 1 keyfile"
	default:
		a.State.KeyfileLabel = "Using " + strconv.Itoa(len(a.State.Keyfiles)) + " keyfiles"
	}

	giu.Update()
	return true
}
