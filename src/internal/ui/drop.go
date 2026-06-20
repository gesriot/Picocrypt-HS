package ui

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"Picocrypt-NG/internal/volume"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
)

const (
	dropScanBatchSize              = 128
	dropScanFlushInterval          = 50 * time.Millisecond
	startupPathAccessStatus        = "Failed to access startup path"
	startupPathPartialAccessStatus = "Some startup paths could not be accessed"
)

type scannedFile struct {
	path string
	size int64
}

var startupPathStat = os.Stat

func isIgnoredStartupArg(path string) bool {
	return path == "" || strings.HasPrefix(path, "-psn_")
}

func isDecryptVolumePath(path string) bool {
	if fileops.IsSplitChunkPath(path) {
		return true
	}

	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".pcv")
}

func trimPCVSuffix(path string) string {
	if !strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".pcv") {
		return path
	}

	return path[:len(path)-4]
}

func collectStartupPaths(paths []string, statFn func(string) (os.FileInfo, error)) ([]string, error) {
	validPaths := make([]string, 0, len(paths))
	var firstErr error

	for _, path := range paths {
		if isIgnoredStartupArg(path) {
			continue
		}

		if _, err := statFn(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("startup path %q: %w", path, err)
			}
			continue
		}

		validPaths = append(validPaths, path)
	}

	return validPaths, firstErr
}

// applyStartupPaths reuses drag-and-drop handling for files passed at GUI startup.
func (a *App) applyStartupPaths(paths []string) {
	validPaths, err := collectStartupPaths(paths, startupPathStat)
	if len(validPaths) == 0 {
		if err != nil {
			a.State.MainStatus = startupPathAccessStatus
			a.State.MainStatusColor = util.RED
			a.refreshUI()
		}
		return
	}

	a.onDrop(validPaths)
	if err != nil {
		a.State.MainStatus = startupPathPartialAccessStatus
		a.State.MainStatusColor = util.YELLOW
		a.refreshUI()
	}
}

func (a *App) applyFolderWalkError() {
	a.State.SetScanning(false)
	a.resetUI()
	a.State.MainStatus = "Failed to walk through dropped items"
	a.State.MainStatusColor = util.RED
	a.refreshUI()
}

func (a *App) appendScannedFiles(files []scannedFile) {
	if len(files) == 0 {
		return
	}

	for _, file := range files {
		a.State.AllFiles = append(a.State.AllFiles, file.path)
		a.State.CompressTotal += file.size
		a.State.RequiredFreeSpace += file.size
	}
	a.State.InputLabel = fmt.Sprintf("Scanning files... (%s)", util.Sizeify(a.State.CompressTotal))
	a.refreshUI()
}

// onDrop handles files and folders dropped onto the window (matches original exactly).
func (a *App) onDrop(names []string) {
	// If keyfile modal is open, handle as keyfiles
	if a.State.ShowKeyfile {
		a.handleKeyfileDrop(names)
		return
	}

	// Prevent race condition: ignore new drops while scanning or working
	// This prevents multiple goroutines from simultaneously modifying AllFiles
	if a.State.IsScanning() || a.State.IsWorking() {
		return
	}

	a.State.SetScanning(true)
	a.State.CompressDone = 0
	a.State.CompressTotal = 0
	// Reset UI synchronously - onDrop runs on UI thread, so fyne.Do() is not needed
	// Using fyne.Do() here would cause a race condition where Mode gets cleared
	// AFTER it's set below, because fyne.Do() queues the call for later execution
	a.resetUI()

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			a.State.MainStatus = "Failed to stat dropped item"
			a.State.MainStatusColor = util.RED
			a.State.SetScanning(false)
			fyne.Do(func() {
				a.refreshUI()
			})
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			a.State.Mode = "encrypt"
			a.State.InputLabel = "1 folder"
			a.State.StartLabel = "Zip and Encrypt"
			a.State.OnlyFolders = append(a.State.OnlyFolders, names[0])
			a.State.InputFile = filepath.Join(filepath.Dir(names[0]),
				"encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			a.State.OutputFile = a.State.InputFile + ".pcv"
		} else {
			// A file was dropped
			a.State.RequiredFreeSpace = stat.Size()

			// Is the file a part of a split volume?
			isSplit := fileops.IsSplitChunkPath(names[0])

			// Decide if encrypting or decrypting
			if isDecryptVolumePath(names[0]) {
				a.handleDecryptDrop(names[0], isSplit)
				// For decrypt, no folder scanning needed
				a.State.SetScanning(false)
				fyne.Do(func() {
					a.refreshUI()
					a.refreshAdvanced()
				})
				return
			} else {
				// Encrypting a single file
				a.State.Mode = "encrypt"
				a.State.InputFile = names[0]
				a.State.InputLabel = "1 file"
				a.State.StartLabel = "Encrypt"
				// Set output file based on compress state
				if a.State.Compress {
					a.State.OutputFile = names[0] + ".zip.pcv"
				} else {
					a.State.OutputFile = names[0] + ".pcv"
				}
				a.State.OnlyFiles = append(a.State.OnlyFiles, names[0])
				a.State.AllFiles = append(a.State.AllFiles, names[0])
				// Add to compressTotal for size display (like original line 1077)
				a.State.CompressTotal += stat.Size()
			}
		}
	} else {
		// Multiple items dropped - always encrypt
		a.handleMultipleDrop(names)
	}

	if len(a.State.OnlyFolders) == 0 {
		a.State.InputLabel = fmt.Sprintf("%s (%s)", a.State.InputLabel, util.Sizeify(a.State.CompressTotal))
		a.State.SetScanning(false)
		a.refreshUI()
		a.refreshAdvanced()
		return
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles' (matches original lines 1133-1173)
	go func() {
		oldInputLabel := a.State.InputLabel
		pendingFiles := make([]scannedFile, 0, dropScanBatchSize)
		lastFlush := time.Now()

		flushPendingFiles := func() {
			if len(pendingFiles) == 0 {
				return
			}

			batch := append([]scannedFile(nil), pendingFiles...)
			pendingFiles = pendingFiles[:0]
			fyne.DoAndWait(func() {
				a.appendScannedFiles(batch)
			})
			lastFlush = time.Now()
		}

		for _, name := range a.State.OnlyFolders {
			if filepath.Walk(name, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					fyne.DoAndWait(func() {
						a.applyFolderWalkError()
					})
					return err
				}
				// If 'path' is a valid regular file, add to 'allFiles'
				// Use info.Mode().IsRegular() to skip symlinks, devices, pipes, sockets
				if info.Mode().IsRegular() {
					pendingFiles = append(pendingFiles, scannedFile{path: path, size: info.Size()})
					if len(pendingFiles) >= dropScanBatchSize || time.Since(lastFlush) >= dropScanFlushInterval {
						flushPendingFiles()
					}
				}
				return nil
			}) != nil {
				fyne.DoAndWait(func() {
					a.applyFolderWalkError()
				})
				return
			}
		}

		flushPendingFiles()

		fyne.DoAndWait(func() {
			a.State.InputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, util.Sizeify(a.State.CompressTotal))
			a.State.SetScanning(false)
			a.refreshUI()
			a.refreshAdvanced()
		})
	}()
}

func (a *App) applyDropError(status string, closeKeyfileModal bool) {
	if closeKeyfileModal && a.keyfileModal != nil {
		a.keyfileModal.Hide()
	}
	a.resetUI()
	a.State.MainStatus = status
	a.State.MainStatusColor = util.RED
	a.refreshUI()
}

// handleDecryptDrop handles a .pcv file being dropped for decryption.
func (a *App) handleDecryptDrop(name string, isSplit bool) {
	a.State.Mode = "decrypt"
	a.State.InputLabel = "Volume for decryption"
	a.State.StartLabel = "Decrypt"
	a.State.CommentsLabel = "Comments (read-only):"
	a.State.CommentsDisabled = true

	// Add the file to onlyFiles (required for UI enable/disable logic)
	a.State.OnlyFiles = append(a.State.OnlyFiles, name)

	// Get the correct input and output filenames
	if isSplit {
		basePath, ok := fileops.SplitChunkBase(name)
		if !ok {
			a.applyDropError("Failed to derive split volume path", false)
			return
		}
		name = basePath
		a.State.InputFile = name
		a.State.OutputFile = trimPCVSuffix(name)
		a.State.Recombine = true

		// Find out the number of split chunks
		totalFiles := 0
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", a.State.InputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			a.State.CompressTotal += stat.Size()
		}
		a.State.RequiredFreeSpace = a.State.CompressTotal
	} else {
		a.State.InputFile = name
		a.State.OutputFile = trimPCVSuffix(name)
	}

	// Open the input file in read-only mode
	var fin *os.File
	var err error
	if isSplit {
		// #nosec G304 -- user-dropped file path
		fin, err = os.Open(name + ".0")
	} else {
		// #nosec G304 -- user-dropped file path
		fin, err = os.Open(name)
	}
	if err != nil {
		fyne.Do(func() {
			a.applyDropError("Read access denied", false)
		})
		return
	}
	defer func() { _ = fin.Close() }()

	// Parse the header through the single validated parser (SEC-01/UI-01/D-01).
	// previewHeader is pure + UI-free; it shares the ^\d{5}$ comment-length
	// guard (+ D-02 bound) and the anchored version regex used at decrypt time,
	// so a crafted comment-length field can never drive an over-allocation here.
	res, err := previewHeader(fin, a.rsCodecs)
	if err != nil {
		switch {
		case errors.Is(err, header.ErrInvalidVersion):
			// Version field does not match ^v\d\.\d{2}$ — the volume may have a
			// plausible-deniability wrapper (its leading bytes are random).
			a.State.Deniability = true
			a.State.MainStatus = "Cannot read header, volume may be deniable"
			return
		case errors.Is(err, header.ErrInvalidCommentLength):
			// Malformed comment length is a non-comment header-field failure:
			// it must not leave the volume looking startable.
			a.State.MainStatus = "The volume header is damaged"
			a.State.MainStatusColor = util.RED
			return
		default:
			a.State.MainStatus = "The volume header is damaged"
			a.State.MainStatusColor = util.RED
			return
		}
	} else if res.DecodeError != nil && res.NonCommentDecodeError {
		a.State.MainStatus = "The volume header is damaged"
		a.State.MainStatusColor = util.RED
		return
	} else if res.DecodeError != nil && res.CommentDecodeError {
		a.State.Comments = "Comments are corrupted"
	} else if res.DecodeError != nil {
		a.State.MainStatus = "The volume header is damaged"
		a.State.MainStatusColor = util.RED
		return
	} else {
		a.State.Comments = res.Header.Comments
	}

	// Update comments entry if it exists
	fyne.Do(func() {
		if a.commentsEntry != nil {
			a.commentsEntry.SetText(a.State.Comments)
		}
	})

	// Parse flags from the decoded header (only when ReadHeader produced one).
	if res != nil {
		flagsStruct := res.Header.Flags
		if flagsStruct.UseKeyfiles {
			a.State.Keyfile = true
			a.State.KeyfileLabel = "Keyfiles required"
		} else {
			a.State.KeyfileLabel = "Not applicable"
		}
		if flagsStruct.KeyfileOrdered {
			a.State.KeyfileOrdered = true
		}
	}

	// Check for deniability
	if volume.IsDeniable(a.State.InputFile, a.rsCodecs) {
		a.State.Deniability = true
	}
}

// handleMultipleDrop handles multiple files/folders being dropped.
// Matches original lines 1081-1131 exactly.
func (a *App) handleMultipleDrop(names []string) {
	a.State.Mode = "encrypt"
	a.State.StartLabel = "Zip and Encrypt"
	files, folders := 0, 0

	// Go through each dropped item and add to corresponding slices
	for _, name := range names {
		stat, err := os.Stat(name)
		if err != nil {
			a.State.MainStatus = "Failed to stat dropped items"
			a.State.MainStatusColor = util.RED
			fyne.Do(func() {
				a.resetUI()
				a.refreshUI()
			})
			return
		}
		if stat.IsDir() {
			folders++
			a.State.OnlyFolders = append(a.State.OnlyFolders, name)
		} else {
			files++
			a.State.OnlyFiles = append(a.State.OnlyFiles, name)
			a.State.AllFiles = append(a.State.AllFiles, name)

			a.State.CompressTotal += stat.Size()
			a.State.RequiredFreeSpace += stat.Size()
			a.State.InputLabel = fmt.Sprintf("Scanning files... (%s)", util.Sizeify(a.State.CompressTotal))
		}
	}

	// Update UI with the number of files and folders selected (matches original lines 1111-1125)
	if folders == 0 {
		a.State.InputLabel = fmt.Sprintf("%d files", files)
	} else if files == 0 {
		a.State.InputLabel = fmt.Sprintf("%d folders", folders)
	} else {
		if files == 1 && folders > 1 {
			a.State.InputLabel = fmt.Sprintf("1 file and %d folders", folders)
		} else if folders == 1 && files > 1 {
			a.State.InputLabel = fmt.Sprintf("%d files and 1 folder", files)
		} else if folders == 1 && files == 1 {
			a.State.InputLabel = "1 file and 1 folder"
		} else {
			a.State.InputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
		}
	}

	// Set the input and output paths (matches original lines 1127-1129)
	a.State.InputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
	a.State.OutputFile = a.State.InputFile + ".pcv"
}

// handleKeyfileDrop processes dropped keyfiles when the modal is open.
func (a *App) handleKeyfileDrop(paths []string) bool {
	if !a.State.ShowKeyfile {
		return false
	}

	// Add keyfiles, checking for duplicates and access
	for _, path := range paths {
		// Check if duplicate
		duplicate := slices.Contains(a.State.Keyfiles, path)

		// Check if accessible and not a directory
		stat, err := os.Stat(path)
		if err != nil {
			a.State.ShowKeyfile = false
			fyne.Do(func() {
				a.applyDropError("Keyfile read access denied", true)
			})
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

	// Update the keyfile list in the modal and increment modalId like original
	a.State.ModalID++
	fyne.Do(func() {
		a.updateKeyfileList()
		a.refreshUI()
	})
	return true
}
