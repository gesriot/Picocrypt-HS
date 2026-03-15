// Package ui provides the Picocrypt NG graphical user interface using Fyne.
package ui

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"

	"fyne.io/fyne/v2"
)

func showOverwriteModalForOutput(outputExists, recursively, chosenViaDialog bool) bool {
	return outputExists && !recursively && !chosenViaDialog
}

type recursiveSettings struct {
	password       string
	keyfile        bool
	keyfiles       []string
	keyfileOrdered bool
	keyfileLabel   string
	comments       string
	paranoid       bool
	reedSolomon    bool
	deniability    bool
	split          bool
	splitSize      string
	splitSelected  int32
	delete         bool
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
	_, outputExists := os.Stat(a.State.OutputFile)
	if showOverwriteModalForOutput(outputExists == nil, a.State.Recursively, a.State.OutputChosenViaSaveDialog) {
		a.showOverwriteModal()
		return
	}

	a.startWork()
}

// startWork begins the encryption/decryption operation.
func (a *App) startWork() {
	a.State.OutputChosenViaSaveDialog = false
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
			// Clean up mobile temp files after operation completes
			if isMobile() {
				a.CleanupMobileTempFiles()
			}
			fyne.Do(func() {
				a.State.Working = false
				a.State.ShowProgress = false
				if a.progressModal != nil {
					a.progressModal.Hide()
				}
				// Rebuild advanced section (clears options, resizes window for empty mode)
				a.updateAdvancedSection()
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
	fyne.DoAndWait(func() {
		a.State.Working = true
	})
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
	saved := recursiveSettings{
		password:       a.State.Password,
		keyfile:        a.State.Keyfile,
		keyfiles:       append([]string(nil), a.State.Keyfiles...),
		keyfileOrdered: a.State.KeyfileOrdered,
		keyfileLabel:   a.State.KeyfileLabel,
		comments:       a.State.Comments,
		paranoid:       a.State.Paranoid,
		reedSolomon:    a.State.ReedSolomon,
		deniability:    a.State.Deniability,
		split:          a.State.Split,
		splitSize:      a.State.SplitSize,
		splitSelected:  a.State.SplitSelected,
		delete:         a.State.Delete,
	}

	files := make([]string, len(a.State.AllFiles))
	copy(files, a.State.AllFiles)

	go func() {
		var failedCount int
		var successCount int

		for i, file := range files {
			a.applyRecursiveSelection(file, saved, i+1, len(files))

			if a.doWork() {
				successCount++
			} else {
				failedCount++
			}

			// Reset Working flag so next iteration's onDrop() isn't blocked
			// (onDrop has a guard to prevent race conditions during scanning/working)
			fyne.DoAndWait(func() {
				a.State.Working = false
			})

			if a.cancelled.Load() {
				// Clean up mobile temp files after cancellation
				if isMobile() {
					a.CleanupMobileTempFiles()
				}
				fyne.DoAndWait(func() {
					a.State.Working = false
					a.State.ShowProgress = false
					if a.progressModal != nil {
						a.progressModal.Hide()
					}
					a.updateAdvancedSection()
					a.updateUIState()
				})
				return
			}
		}

		// Clean up mobile temp files after recursive operation completes
		if isMobile() {
			a.CleanupMobileTempFiles()
		}

		fyne.DoAndWait(func() {
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
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateAdvancedSection()
			a.updateUIState()
		})
	}()
}

func (a *App) applyRecursiveSelection(file string, saved recursiveSettings, index, total int) {
	status := fmt.Sprintf("Processing file %d/%d...", index, total)

	fyne.DoAndWait(func() {
		a.onDrop([]string{file})

		a.State.Password = saved.password
		a.State.CPassword = saved.password
		a.State.Keyfile = saved.keyfile
		a.State.Keyfiles = append([]string(nil), saved.keyfiles...)
		a.State.KeyfileOrdered = saved.keyfileOrdered
		a.State.KeyfileLabel = saved.keyfileLabel
		a.State.Comments = saved.comments
		a.State.Paranoid = saved.paranoid
		a.State.ReedSolomon = saved.reedSolomon
		if a.State.Mode != "decrypt" {
			a.State.Deniability = saved.deniability
		}
		a.State.Split = saved.split
		a.State.SplitSize = saved.splitSize
		a.State.SplitSelected = saved.splitSelected
		a.State.Delete = saved.delete
		a.State.SetPopupStatus(status)
		_ = a.boundStatus.Set(status)
	})
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

	err := volume.Encrypt(context.Background(), req)
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

	// Clear UI widgets to match the reset state
	fyne.Do(func() {
		if a.passwordEntry != nil {
			a.passwordEntry.SetText("")
		}
		if a.cPasswordEntry != nil {
			a.cPasswordEntry.SetText("")
		}
		if a.commentsEntry != nil {
			a.commentsEntry.SetText("")
		}
		a.updatePasswordStrength()
		a.updateValidation()
	})

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
		VerifyFirst:  a.State.VerifyFirst,
		AutoUnzip:    a.State.AutoUnzip,
		SameLevel:    a.State.SameLevel,
		Recombine:    a.State.Recombine,
		Deniability:  a.State.Deniability,
		Reporter:     reporter,
		RSCodecs:     a.rsCodecs,
		Kept:         &kept,
	}

	err := volume.Decrypt(context.Background(), req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.MainStatus = err.Error()
			a.State.MainStatusColor = util.RED
		}
		return false
	}

	a.State.ResetUI()

	// Clear UI widgets to match the reset state
	fyne.Do(func() {
		if a.passwordEntry != nil {
			a.passwordEntry.SetText("")
		}
		if a.cPasswordEntry != nil {
			a.cPasswordEntry.SetText("")
		}
		if a.commentsEntry != nil {
			a.commentsEntry.SetText("")
		}
		a.updatePasswordStrength()
		a.updateValidation()
	})

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

// CreateReporter creates a UIReporter for progress updates.
func (a *App) CreateReporter() *app.UIReporter {
	return app.NewUIReporter(
		func(text string) {
			fyne.Do(func() {
				a.State.SetPopupStatus(text)
			})
			_ = a.boundStatus.Set(text)
		},
		func(fraction float32, info string) {
			fyne.Do(func() {
				a.State.SetProgress(fraction, info)
			})
			_ = a.boundProgress.Set(float64(fraction))
		},
		func(can bool) {
			fyne.Do(func() {
				a.State.SetCanCancel(can)
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
			return a.cancelled.Load()
		},
	)
}
