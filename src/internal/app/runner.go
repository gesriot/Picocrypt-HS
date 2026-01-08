package app

import (
	"fmt"
	"sync"

	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"
)

// Reporter implements volume.ProgressReporter for UI integration.
type Reporter struct {
	mu           sync.RWMutex
	status       string
	progress     float32
	progressInfo string
	canCancel    bool
	cancelled    bool
	speed        float64
	eta          string
	updateFn     func() // Called to trigger UI refresh
}

// NewReporter creates a new progress reporter.
func NewReporter(updateFn func()) *Reporter {
	return &Reporter{
		status:   "Ready",
		updateFn: updateFn,
	}
}

// SetStatus implements volume.ProgressReporter.
func (r *Reporter) SetStatus(text string) {
	r.mu.Lock()
	r.status = text
	r.mu.Unlock()
	if r.updateFn != nil {
		r.updateFn()
	}
}

// SetProgress implements volume.ProgressReporter.
func (r *Reporter) SetProgress(fraction float32, info string) {
	r.mu.Lock()
	r.progress = fraction
	r.progressInfo = info
	r.mu.Unlock()
	if r.updateFn != nil {
		r.updateFn()
	}
}

// SetCanCancel implements volume.ProgressReporter.
func (r *Reporter) SetCanCancel(can bool) {
	r.mu.Lock()
	r.canCancel = can
	r.mu.Unlock()
	if r.updateFn != nil {
		r.updateFn()
	}
}

// Update implements volume.ProgressReporter.
func (r *Reporter) Update() {
	if r.updateFn != nil {
		r.updateFn()
	}
}

// IsCancelled implements volume.ProgressReporter.
func (r *Reporter) IsCancelled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cancelled
}

// Cancel marks the operation as cancelled.
func (r *Reporter) Cancel() {
	r.mu.Lock()
	r.cancelled = true
	r.mu.Unlock()
}

// GetStatus returns the current status.
func (r *Reporter) GetStatus() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

// GetProgress returns the current progress.
func (r *Reporter) GetProgress() (float32, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.progress, r.progressInfo
}

// GetCanCancel returns whether cancel is allowed.
func (r *Reporter) GetCanCancel() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.canCancel
}

// GetSpeed returns the current operation speed.
func (r *Reporter) GetSpeed() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.speed
}

// GetETA returns the estimated time remaining.
func (r *Reporter) GetETA() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.eta
}

// Reset resets the reporter state.
func (r *Reporter) Reset() {
	r.mu.Lock()
	r.status = "Ready"
	r.progress = 0
	r.progressInfo = ""
	r.canCancel = false
	r.cancelled = false
	r.speed = 0
	r.eta = ""
	r.mu.Unlock()
}

// Runner orchestrates encryption/decryption operations.
type Runner struct {
	state    *State
	reporter *Reporter
	mu       sync.RWMutex
}

// NewRunner creates a new operation runner.
func NewRunner(state *State, updateFn func()) *Runner {
	return &Runner{
		state:    state,
		reporter: NewReporter(updateFn),
	}
}

// GetReporter returns the progress reporter.
func (r *Runner) GetReporter() *Reporter {
	return r.reporter
}

// Encrypt starts an encryption operation.
func (r *Runner) Encrypt() error {
	r.mu.Lock()
	r.state.Working = true
	r.reporter.Reset()
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.state.Working = false
		r.mu.Unlock()
	}()

	// Build file list
	files := make([]string, 0, len(r.state.OnlyFiles)+len(r.state.OnlyFolders))
	files = append(files, r.state.OnlyFiles...)
	files = append(files, r.state.AllFiles...) // Include files from folders

	// Convert split unit
	var splitUnit fileops.SplitUnit
	switch r.state.SplitSelected {
	case 0:
		splitUnit = fileops.SplitUnitKiB
	case 1:
		splitUnit = fileops.SplitUnitMiB
	case 2:
		splitUnit = fileops.SplitUnitGiB
	case 3:
		splitUnit = fileops.SplitUnitTiB
	case 4:
		splitUnit = fileops.SplitUnitTotal
	}

	// Parse split size
	chunkSize := 0
	if r.state.Split && r.state.SplitSize != "" {
		// Parse the split size string
		var size int
		n, err := fmt.Sscanf(r.state.SplitSize, "%d", &size)
		if err != nil || n != 1 || size <= 0 {
			return fmt.Errorf("invalid split size: %q (must be a positive integer)", r.state.SplitSize)
		}
		chunkSize = size
	}

	req := &volume.EncryptRequest{
		InputFiles:     files,
		OnlyFolders:    r.state.OnlyFolders,
		OnlyFiles:      r.state.OnlyFiles,
		OutputFile:     r.state.OutputFile,
		Password:       r.state.Password,
		Keyfiles:       r.state.Keyfiles,
		KeyfileOrdered: r.state.KeyfileOrdered,
		Comments:       r.state.Comments,
		Paranoid:       r.state.Paranoid,
		ReedSolomon:    r.state.ReedSolomon,
		Deniability:    r.state.Deniability,
		Compress:       r.state.Compress,
		Split:          r.state.Split,
		ChunkSize:      chunkSize,
		ChunkUnit:      splitUnit,
		Reporter:       r.reporter,
		RSCodecs:       r.state.RSCodecs,
	}

	return volume.Encrypt(req)
}

// Decrypt starts a decryption operation.
func (r *Runner) Decrypt() error {
	r.mu.Lock()
	r.state.Working = true
	r.reporter.Reset()
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.state.Working = false
		r.mu.Unlock()
	}()

	req := &volume.DecryptRequest{
		InputFile:    r.state.InputFile,
		OutputFile:   r.state.OutputFile,
		Password:     r.state.Password,
		Keyfiles:     r.state.Keyfiles,
		ForceDecrypt: r.state.Keep,
		AutoUnzip:    r.state.AutoUnzip,
		SameLevel:    r.state.SameLevel,
		Recombine:    r.state.Recombine,
		Reporter:     r.reporter,
		RSCodecs:     r.state.RSCodecs,
	}

	return volume.Decrypt(req)
}

// Cancel attempts to cancel the current operation.
func (r *Runner) Cancel() {
	r.reporter.Cancel()
}

// IsWorking returns true if an operation is in progress.
func (r *Runner) IsWorking() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.state.Working
}
