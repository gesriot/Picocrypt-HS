package ui

import (
	"context"
	"errors"
	"time"

	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
)

const (
	openedPathReadyTimeout = 45 * time.Second

	openedPathsPreparingStatus = "Preparing iCloud files"
	openedPathsTimeoutStatus   = "Some iCloud files are not downloaded"
)

var (
	openedPathPollInterval             = 200 * time.Millisecond
	openedPathCloudSettleDelay         = 1500 * time.Millisecond
	openedPathCloudCancelSuppressDelay = 1500 * time.Millisecond
	beforeOpenedPathReadyApply         = func() {}
)

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
	a.openReadinessGeneration++
	a.openReadinessCancel = nil
	a.openReadinessPaths = nil
	a.openReadinessCollectLate = false
	a.openReadinessLastAppend = time.Time{}
	if cancel != nil && activePaths {
		a.openReadinessSuppressUntil = time.Now().Add(openedPathCloudCancelSuppressDelay)
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

func (a *App) enableLateOpenedPathCollection(generation uint64) {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessGeneration != generation || a.openReadinessCancel == nil {
		return
	}
	a.openReadinessCollectLate = true
}

func (a *App) mergeLateOpenedPaths(paths []string) bool {
	a.openReadinessMu.Lock()
	defer a.openReadinessMu.Unlock()
	if a.openReadinessCancel == nil || !a.openReadinessCollectLate {
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

func (a *App) finishOpenedPathReadinessIfPathsCurrent(generation uint64, paths []string) bool {
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
		a.openReadinessSuppressUntil = now.Add(openedPathCloudCancelSuppressDelay)
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
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}
		a.State.MainStatus = openedPathsPreparingStatus
		a.State.MainStatusColor = util.YELLOW
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

	ctx, generation := a.beginOpenedPathReadiness(normalized)
	go a.waitForOpenedPathsAndApply(ctx, generation)
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
			if a.applyReadyOpenedPaths(generation, paths) {
				return
			}
			if !a.isOpenedPathReadinessCurrent(generation) {
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

func (a *App) applyReadyOpenedPaths(generation uint64, paths []string) bool {
	applied := false
	beforeOpenedPathReadyApply()
	fyne.DoAndWait(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}
		if !a.finishOpenedPathReadinessIfPathsCurrent(generation, paths) {
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
		a.State.MainStatus = startupPathAccessStatus
		a.State.MainStatusColor = util.RED
		a.refreshUI()
	})
}

func (a *App) applyOpenedPathReadinessTimeout(generation uint64) {
	fyne.Do(func() {
		if !a.openedPathReadinessCanUpdateUI(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.MainStatus = openedPathsTimeoutStatus
		a.State.MainStatusColor = util.YELLOW
		a.refreshUI()
	})
}
