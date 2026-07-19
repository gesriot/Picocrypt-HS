// Package app provides application state management and operations orchestration.
package app

import "Picocrypt-NG/internal/volume"

// Ensure UIReporter implements volume.ProgressReporter
var _ volume.ProgressReporter = (*UIReporter)(nil)

// UIReporter bridges the volume module with the main UI.
// It implements volume.ProgressReporter and updates UI state.
type UIReporter struct {
	onStatus    func(text string)
	onProgress  func(fraction float32, info string)
	onCanCancel func(can bool)
	checkCancel func() bool
}

// NewUIReporter creates a new UI reporter with the given callbacks.
func NewUIReporter(
	onStatus func(string),
	onProgress func(float32, string),
	onCanCancel func(bool),
	checkCancel func() bool,
) *UIReporter {
	return &UIReporter{
		onStatus:    onStatus,
		onProgress:  onProgress,
		onCanCancel: onCanCancel,
		checkCancel: checkCancel,
	}
}

// SetStatus implements volume.ProgressReporter.
func (r *UIReporter) SetStatus(text string) {
	r.onStatus(text)
}

// SetProgress implements volume.ProgressReporter.
func (r *UIReporter) SetProgress(fraction float32, info string) {
	r.onProgress(fraction, info)
}

// SetCanCancel implements volume.ProgressReporter.
func (r *UIReporter) SetCanCancel(can bool) {
	r.onCanCancel(can)
}

// Update implements volume.ProgressReporter. The callbacks update Fyne data
// bindings directly, so there is no additional full-render dispatch to perform.
func (r *UIReporter) Update() {
}

// IsCancelled implements volume.ProgressReporter.
func (r *UIReporter) IsCancelled() bool {
	return r.checkCancel()
}
