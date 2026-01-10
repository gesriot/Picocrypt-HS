// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// updateAdvancedSection updates the advanced options based on mode.
func (a *App) updateAdvancedSection() {
	// Use mobile-specific advanced section on mobile
	if isMobile() {
		a.updateMobileAdvancedSection()
		return
	}

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
	// Row 1: Force decrypt + Verify first
	a.forceDecryptCheck = widget.NewCheck("Force decrypt", func(checked bool) {
		a.State.Keep = checked
	})
	a.forceDecryptCheck.SetChecked(a.State.Keep)

	a.verifyFirstCheck = widget.NewCheck("Verify first", func(checked bool) {
		a.State.VerifyFirst = checked
	})
	a.verifyFirstCheck.SetChecked(a.State.VerifyFirst)

	row1 := container.NewGridWithColumns(2, a.forceDecryptCheck, a.verifyFirstCheck)

	// Row 2: Delete volume + Auto unzip
	a.deleteVolumeCheck = widget.NewCheck("Delete volume", func(checked bool) {
		a.State.Delete = checked
	})
	a.deleteVolumeCheck.SetChecked(a.State.Delete)

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

	row2 := container.NewGridWithColumns(2, a.deleteVolumeCheck, a.autoUnzipCheck)

	// Row 3: Same level (only if auto unzip is relevant)
	a.sameLevelCheck = widget.NewCheck("Same level", func(checked bool) {
		a.State.SameLevel = checked
	})
	a.sameLevelCheck.SetChecked(a.State.SameLevel)

	row3 := container.NewGridWithColumns(2, a.sameLevelCheck, widget.NewLabel(""))

	a.advancedContainer.Add(row1)
	a.advancedContainer.Add(row2)
	a.advancedContainer.Add(row3)

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

// updateAdvancedDisableState updates the disable state of advanced options.
func (a *App) updateAdvancedDisableState() {
	hasCredentials := len(a.State.Keyfiles) > 0 || a.State.Password != ""
	passwordsMatch := a.State.Mode != "encrypt" || a.State.Password == a.State.CPassword
	advancedDisabled := !hasCredentials || !passwordsMatch

	if a.State.Mode != "decrypt" {
		a.updateEncryptOptionsState(advancedDisabled)
	} else {
		a.updateDecryptOptionsState(advancedDisabled)
	}
}

// updateEncryptOptionsState updates encrypt mode option states.
func (a *App) updateEncryptOptionsState(advancedDisabled bool) {
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
}

// updateDecryptOptionsState updates decrypt mode option states.
func (a *App) updateDecryptOptionsState(advancedDisabled bool) {
	if a.forceDecryptCheck != nil {
		if advancedDisabled || a.State.Deniability {
			a.forceDecryptCheck.Disable()
		} else {
			a.forceDecryptCheck.Enable()
		}
	}

	if a.verifyFirstCheck != nil {
		if advancedDisabled {
			a.verifyFirstCheck.Disable()
		} else {
			a.verifyFirstCheck.Enable()
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
