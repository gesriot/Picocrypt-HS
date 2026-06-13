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

// onClickStart handles the Start button click.
func (a *App) onClickStart() {
	a.cancelOpenedPathReadiness()

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
	a.State.SetShowProgress(true)
	a.State.FastDecode = true
	a.State.SetCanCancel(true)
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
				a.State.SetWorking(false)
				a.State.SetShowProgress(false)
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
		a.State.SetWorking(true)
	})
	reporter := a.CreateReporter()

	if a.State.IsEncrypting() {
		return a.doEncrypt(reporter)
	}
	return a.doDecrypt(reporter)
}

// startRecursiveWork handles batch processing of multiple files individually.
func (a *App) startRecursiveWork() {
	if len(a.State.AllFiles) == 0 {
		a.State.SetStatus("No files to process", util.YELLOW)
		a.State.SetWorking(false)
		a.State.SetShowProgress(false)
		fyne.Do(func() {
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateUIState()
		})
		return
	}

	// Capture all settings under one RLock before they get cleared by
	// onDrop/resetUI, then re-apply them per file via the locked accessor (APP-02).
	saved := a.State.RecursiveSnapshot()

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
				a.State.SetWorking(false)
			})

			if a.cancelled.Load() {
				// Clean up mobile temp files after cancellation
				if isMobile() {
					a.CleanupMobileTempFiles()
				}
				fyne.DoAndWait(func() {
					a.State.SetWorking(false)
					a.State.SetShowProgress(false)
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
			a.State.SetWorking(false)
			a.State.SetShowProgress(false)
			if failedCount == 0 {
				a.State.SetStatus(fmt.Sprintf("Completed (%d files)", successCount), util.GREEN)
			} else if successCount == 0 {
				a.State.SetStatus(fmt.Sprintf("Failed (all %d files)", failedCount), util.RED)
			} else {
				a.State.SetStatus(fmt.Sprintf("Completed (%d ok, %d failed)", successCount, failedCount), util.YELLOW)
			}
			if a.progressModal != nil {
				a.progressModal.Hide()
			}
			a.updateAdvancedSection()
			a.updateUIState()
		})
	}()
}

func (a *App) applyRecursiveSelection(file string, saved app.RecursiveSnapshot, index, total int) {
	status := fmt.Sprintf("Processing file %d/%d...", index, total)

	fyne.DoAndWait(func() {
		a.onDrop([]string{file})
		a.State.ApplyRecursiveSelection(saved)
		a.State.SetPopupStatus(status)
		_ = a.boundStatus.Set(status)
	})
}

// doEncrypt performs encryption using the volume package.
func (a *App) doEncrypt(reporter *app.UIReporter) bool {
	// APP-02: read every request-building field once, consistently, under a
	// single RLock instead of ~15 bare cross-goroutine field reads.
	snap := a.State.Snapshot()

	var chunkUnit fileops.SplitUnit
	switch snap.SplitSelected {
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
	if snap.SplitSize != "" {
		n, err := strconv.Atoi(snap.SplitSize)
		if err != nil || n <= 0 {
			a.State.SetStatus("Invalid split size", util.RED)
			return false
		}
		chunkSize = n
	}

	shouldDelete := snap.Delete

	req := &volume.EncryptRequest{
		InputFile:      snap.InputFile,
		InputFiles:     snap.InputFiles,
		OnlyFolders:    snap.OnlyFolders,
		OnlyFiles:      snap.OnlyFiles,
		OutputFile:     snap.OutputFile,
		Password:       snap.Password,
		Keyfiles:       snap.Keyfiles,
		KeyfileOrdered: snap.KeyfileOrdered,
		Comments:       snap.Comments,
		Paranoid:       snap.Paranoid,
		ReedSolomon:    snap.ReedSolomon,
		Deniability:    snap.Deniability,
		Compress:       snap.Compress,
		Split:          snap.Split,
		ChunkSize:      chunkSize,
		ChunkUnit:      chunkUnit,
		Reporter:       reporter,
		RSCodecs:       a.rsCodecs,
	}

	filesToDelete := append([]string(nil), snap.InputFiles...)
	foldersToDelete := append([]string(nil), snap.OnlyFolders...)
	inputFileToDelete := snap.InputFile

	err := volume.Encrypt(context.Background(), req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.SetStatus(err.Error(), util.RED)
		}
		return false
	}

	a.State.ResetUI()
	a.State.SetStatus("Completed", util.GREEN)

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
			a.State.SetStatus("Completed (some files couldn't be deleted)", util.YELLOW)
		}
	}

	return true
}

// doDecrypt performs decryption using the volume package.
func (a *App) doDecrypt(reporter *app.UIReporter) bool {
	kept := false

	// APP-02: snapshot the request-building fields once under one RLock.
	snap := a.State.Snapshot()

	shouldDelete := snap.Delete
	recombine := snap.Recombine
	inputFile := snap.InputFile

	req := &volume.DecryptRequest{
		InputFile:    snap.InputFile,
		OutputFile:   snap.OutputFile,
		Password:     snap.Password,
		Keyfiles:     snap.Keyfiles,
		ForceDecrypt: snap.Keep,
		VerifyFirst:  snap.VerifyFirst,
		AutoUnzip:    snap.AutoUnzip,
		SameLevel:    snap.SameLevel,
		Recombine:    snap.Recombine,
		Deniability:  snap.Deniability,
		Reporter:     reporter,
		RSCodecs:     a.rsCodecs,
		Kept:         &kept,
	}

	err := volume.Decrypt(context.Background(), req)
	if err != nil {
		if !a.cancelled.Load() {
			a.State.SetStatus(err.Error(), util.RED)
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
		a.State.SetKept(true)
		a.State.SetStatus("The input file was modified. Please be careful", util.YELLOW)
	} else {
		a.State.SetStatus("Completed", util.GREEN)
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
			a.State.SetStatus("Completed (volume couldn't be deleted)", util.YELLOW)
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
