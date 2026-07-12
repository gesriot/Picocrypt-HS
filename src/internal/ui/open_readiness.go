package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/util"
	"context"
	"errors"
	"time"

	"fyne.io/fyne/v2"
)

const (
	openedPathReadyTimeout = 45 * time.Second
)

var (
	openedPathPollInterval             = 200 * time.Millisecond
	openedPathCloudSettleDelay         = 1500 * time.Millisecond
	openedPathCloudCancelSuppressDelay = 1500 * time.Millisecond
	openedPathCloudPostApplyMergeDelay = 5 * time.Second
	beforeOpenedPathReadyApply         = func() {}
)

func openedPathsPreparingStatus() string {
	return tr("opened_paths.preparing", "Preparing iCloud files")
}

func openedPathsTimeoutStatus() string {
	return tr("opened_paths.timeout", "Some iCloud files are not downloaded")
}

type openedPathReadinessState int

const (
	openedPathReady openedPathReadinessState = iota
	openedPathPending
	openedPathMissing
	openedPathError
)

type openedPathReadiness struct {
	Path         string
	State        openedPathReadinessState
	Err          error
	IsUbiquitous bool
	IsDir        bool
}

type openedPathReadinessResult []openedPathReadiness

type openedPathReadinessCheck func(context.Context, []string) openedPathReadinessResult

var checkOpenedPathReadiness openedPathReadinessCheck = defaultOpenedPathReadiness

func normalizeOpenedPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if isIgnoredStartupArg(path) {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func (r openedPathReadinessResult) allReady() bool {
	if len(r) == 0 {
		return false
	}
	for _, item := range r {
		if item.State != openedPathReady {
			return false
		}
	}
	return true
}

func (r openedPathReadinessResult) terminalError() error {
	for _, item := range r {
		if item.State != openedPathMissing && item.State != openedPathError {
			continue
		}
		if item.Err != nil {
			return item.Err
		}
		return errors.New("opened path is not available")
	}
	return nil
}

func (r openedPathReadinessResult) hasUbiquitousFile() bool {
	for _, item := range r {
		if item.IsUbiquitous && !item.IsDir {
			return true
		}
	}
	return false
}

// hasUbiquitousItem reports whether any opened item (file or folder) lives in
// iCloud. Cloud-backed gestures are the ones Finder/AppKit may split into
// several openURLs: batches, so applying them keeps a merge window open for
// late batches of the same gesture (issue #127).
func (r openedPathReadinessResult) hasUbiquitousItem() bool {
	for _, item := range r {
		if item.IsUbiquitous {
			return true
		}
	}
	return false
}

func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-timer.C:
		return false
	}
}

func (a *App) cancelOpenedPathReadiness() {
	a.openReadinessMu.Lock()
	cancel := a.openReadinessCancel
	activePaths := len(a.openReadinessPaths) > 0
	freshCloudApply := a.cloudApplyMergeableLocked()
	appliedAt := a.openReadinessAppliedAt
	a.openReadinessGeneration++
	a.openReadinessCancel = nil
	a.openReadinessPaths = nil
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Time{}
	a.clearCloudApplyRecordLocked()
	if (cancel != nil && activePaths) || freshCloudApply {
		until := time.Now().Add(openedPathCloudCancelSuppressDelay)
		if freshCloudApply {
			// Stragglers of the cancelled gesture may keep arriving for the
			// rest of the post-apply merge window; suppress them for that long
			// so they cannot stomp the selection the user just made.
			if cloudUntil := appliedAt.Add(openedPathCloudPostApplyMergeDelay); cloudUntil.After(until) {
				until = cloudUntil
			}
		}
		a.openReadinessSuppressUntil = until
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (a *App) beginOpenedPathReadiness(paths []string) (context.Context, uint64) {
	ctx, cancel := context.WithCancel(context.Background())

	a.openReadinessMu.Lock()
	previousCancel := a.openReadinessCancel
	a.openReadinessGeneration++
	generation := a.openReadinessGeneration
	a.openReadinessCancel = cancel
	a.openReadinessPaths = append([]string(nil), paths...)
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Now()
	a.openReadinessMu.Unlock()

	if previousCancel != nil {
		previousCancel()
	}
	return ctx, generation
}

func (a *App) isOpenedPathReadinessCurrent(generation uint64) bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	return a.openReadinessGeneration == generation && a.openReadinessCancel != nil
}

func (a *App) finishOpenedPathReadiness(generation uint64) {
	a.openReadinessMu.Lock()
	cancel := a.openReadinessCancel
	if a.openReadinessGeneration == generation {
		a.openReadinessCancel = nil
		a.openReadinessPaths = nil
		a.openReadinessCollectLate = false
		a.openReadinessLastAppend = time.Time{}
	} else {
		cancel = nil
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// openedPathReadinessUIGuard reports whether the readiness session may touch
// the UI right now. Working always finishes the session: the user started an
// operation and opened paths must not interfere. Scanning finishes it too,
// unless a recent cloud apply marks the scan as belonging to an earlier batch
// of the same open gesture — then the session stays alive so the caller can
// retry after the scan settles. A manual drop, Clear, or Start clears that
// record via cancelOpenedPathReadiness, so foreign scans always finish the
// session, preserving the user's selection.
func (a *App) openedPathReadinessUIGuard(generation uint64) bool {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return false
	}
	snap := a.State.UISnapshot()
	if snap.Working {
		a.finishOpenedPathReadiness(generation)
		return false
	}
	if snap.Scanning {
		if !a.hasRecentCloudApply() {
			a.finishOpenedPathReadiness(generation)
		}
		return false
	}
	return true
}

func (a *App) openedPathReadinessCanUpdateUI(generation uint64) bool {
	if !a.isOpenedPathReadinessCurrent(generation) {
		return false
	}

	snap := a.State.UISnapshot()
	if snap.Working || snap.Scanning {
		a.finishOpenedPathReadiness(generation)
		return false
	}
	return true
}

func (a *App) openedPathReadinessSnapshot(generation uint64) ([]string, bool) {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		return nil, false
	}
	return append([]string(nil), a.openReadinessPaths...), true
}

// enableLateOpenedPathCollection marks the session as cloud-backed so that
// openedPathCloudSettleRemaining holds the apply open for trailing batches.
// It does NOT gate merging: mergeLateOpenedPaths extends any active session.
func (a *App) enableLateOpenedPathCollection(generation uint64) {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		return
	}
	a.openReadinessCollectLate = true
}

// mergeLateOpenedPaths extends the active readiness session with paths from a
// later openURLs: batch of the same gesture. Merging before apply is always
// safe: the session re-checks readiness for the combined set before applying.
func (a *App) mergeLateOpenedPaths(paths []string) bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessCancel == nil {
		return false
	}

	seen := make(map[string]struct{}, len(a.openReadinessPaths)+len(paths))
	for _, path := range a.openReadinessPaths {
		seen[path] = struct{}{}
	}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		a.openReadinessPaths = append(a.openReadinessPaths, path)
	}
	a.openReadinessLastAppend = time.Now()
	return true
}

// cloudApplyMergeableLocked reports whether a cloud-backed opened selection was
// applied recently enough that a late batch of the same gesture must extend it.
// Callers must hold openReadinessMu.
func (a *App) cloudApplyMergeableLocked() bool {
	if len(a.openReadinessAppliedPaths) == 0 {
		return false
	}
	return time.Since(a.openReadinessAppliedAt) <= openedPathCloudPostApplyMergeDelay
}

// clearCloudApplyRecordLocked drops the post-apply merge record. Callers must
// hold openReadinessMu.
func (a *App) clearCloudApplyRecordLocked() {
	a.openReadinessAppliedPaths = nil
	a.openReadinessAppliedAt = time.Time{}
}

// hasRecentCloudApply is the lock-acquiring form of cloudApplyMergeableLocked.
func (a *App) hasRecentCloudApply() bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	return a.cloudApplyMergeableLocked()
}

// mergeWithRecentCloudApply prepends the recently applied cloud selection to a
// late batch of the same open gesture (issue #127: Finder/AppKit can deliver
// one gesture as several openURLs: batches, some of them after the first batch
// was already applied). It returns nil when the batch carries nothing new.
// Outside the merge window the record is dropped and the batch is a separate
// gesture that replaces the selection as usual.
func (a *App) mergeWithRecentCloudApply(paths []string) []string {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if !a.cloudApplyMergeableLocked() {
		a.clearCloudApplyRecordLocked()
		return paths
	}

	seen := make(map[string]struct{}, len(a.openReadinessAppliedPaths)+len(paths))
	merged := make([]string, 0, len(a.openReadinessAppliedPaths)+len(paths))
	for _, path := range a.openReadinessAppliedPaths {
		seen[path] = struct{}{}
		merged = append(merged, path)
	}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		merged = append(merged, path)
	}
	if len(merged) == len(a.openReadinessAppliedPaths) {
		return nil
	}
	return merged
}

func (a *App) finishOpenedPathReadinessIfPathsCurrent(generation uint64, paths []string, hadCloudItem bool) bool {
	a.openReadinessMu.Lock()
	if a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		a.openReadinessMu.Unlock()
		return false
	}
	if !sameStringSlices(a.openReadinessPaths, paths) {
		a.openReadinessMu.Unlock()
		return false
	}
	cancel := a.openReadinessCancel
	a.openReadinessCancel = nil
	a.openReadinessPaths = nil
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Time{}
	if hadCloudItem {
		a.openReadinessAppliedPaths = append([]string(nil), paths...)
		a.openReadinessAppliedAt = time.Now()
	} else {
		a.clearCloudApplyRecordLocked()
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
	return true
}

func (a *App) suppressesOpenedPaths() bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessSuppressUntil.IsZero() {
		return false
	}
	now := time.Now()
	if now.Before(a.openReadinessSuppressUntil) {
		// A straggler stream keeps the window alive, but re-arming must only
		// ever EXTEND it: cancelOpenedPathReadiness may have armed a longer
		// window covering the rest of the post-apply merge period.
		if until := now.Add(openedPathCloudCancelSuppressDelay); until.After(a.openReadinessSuppressUntil) {
			a.openReadinessSuppressUntil = until
		}
		return true
	}
	a.openReadinessSuppressUntil = time.Time{}
	return false
}

func (a *App) openedPathCloudSettleRemaining(generation uint64) time.Duration {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessGeneration != generation || a.openReadinessCancel == nil || !a.openReadinessCollectLate {
		return 0
	}
	if openedPathCloudSettleDelay <= 0 {
		return 0
	}
	remaining := openedPathCloudSettleDelay - time.Since(a.openReadinessLastAppend)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func applyOpenedPathPreparingStatus(a *App, generation uint64) {
	fyne.Do(func() {
		if !a.openedPathReadinessUIGuard(generation) {
			return
		}
		a.State.SetStatusMessage(app.StatusOpenedPathsPreparing, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	})
}

func (a *App) applyOpenedPaths(paths []string) {
	normalized := normalizeOpenedPaths(paths)
	if len(normalized) == 0 {
		return
	}
	if a.suppressesOpenedPaths() {
		return
	}
	if a.mergeLateOpenedPaths(normalized) {
		return
	}
	normalized = a.mergeWithRecentCloudApply(normalized)
	if len(normalized) == 0 {
		return
	}

	ctx, generation := a.beginOpenedPathReadiness(normalized)
	a.openReadinessMu.Lock()
	if a.openReadinessStopped {
		a.openReadinessMu.Unlock()
		a.finishOpenedPathReadiness(generation)
		return
	}
	a.openReadinessTasks.Go(func() {
		a.waitForOpenedPathsAndApply(ctx, generation)
	})
	a.openReadinessMu.Unlock()
}

func (a *App) waitForOpenedPathsAndApply(ctx context.Context, generation uint64) {
	ctx, cancel := context.WithTimeout(ctx, openedPathReadyTimeout)
	defer cancel()

	for {
		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}

		if a.State.IsScanning() && a.hasRecentCloudApply() {
			// A folder scan from an earlier apply of the same gesture is
			// running; skip the readiness checks (cgo per-path queries on
			// darwin) and the UI round-trip until it settles.
			if sleepOrCancel(ctx, openedPathPollInterval) {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					a.applyOpenedPathReadinessTimeout(generation)
				}
				return
			}
			continue
		}

		paths, ok := a.openedPathReadinessSnapshot(generation)
		if !ok {
			return
		}
		result := checkOpenedPathReadiness(ctx, paths)

		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}
		if err := result.terminalError(); err != nil {
			a.applyOpenedPathReadinessError(generation)
			return
		}
		if result.hasUbiquitousFile() {
			a.enableLateOpenedPathCollection(generation)
		}
		if result.allReady() {
			if remaining := a.openedPathCloudSettleRemaining(generation); remaining > 0 {
				applyOpenedPathPreparingStatus(a, generation)
				if sleepOrCancel(ctx, minDuration(openedPathPollInterval, remaining)) {
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						a.applyOpenedPathReadinessTimeout(generation)
					}
					return
				}
				continue
			}
			if a.applyReadyOpenedPaths(generation, paths, result.hasUbiquitousItem()) {
				return
			}
			if !a.isOpenedPathReadinessCurrent(generation) {
				return
			}
			if sleepOrCancel(ctx, openedPathPollInterval) {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					a.applyOpenedPathReadinessTimeout(generation)
				}
				return
			}
			continue
		}

		applyOpenedPathPreparingStatus(a, generation)

		if sleepOrCancel(ctx, openedPathPollInterval) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func sameStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (a *App) applyReadyOpenedPaths(generation uint64, paths []string, hadCloudItem bool) bool {
	applied := false
	beforeOpenedPathReadyApply()
	fyne.DoAndWait(func() {
		if !a.openedPathReadinessUIGuard(generation) {
			return
		}
		if !a.finishOpenedPathReadinessIfPathsCurrent(generation, paths, hadCloudItem) {
			return
		}

		a.applyStartupPaths(paths)
		applied = true
	})
	return applied
}

func (a *App) applyOpenedPathReadinessError(generation uint64) {
	fyne.Do(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.SetStatusMessage(app.StatusStartupPathAccessFailed, util.RED, app.StatusArgs{})
		a.refreshUI()
	})
}

func (a *App) applyOpenedPathReadinessTimeout(generation uint64) {
	fyne.Do(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.SetStatusMessage(app.StatusOpenedPathsTimeout, util.YELLOW, app.StatusArgs{})
		a.refreshUI()
	})
}
