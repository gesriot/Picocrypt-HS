package ui

import (
	"context"
	"errors"
	"os"
	"time"

	"Picocrypt-NG/internal/util"

	"fyne.io/fyne/v2"
)

const (
	openedPathReadyTimeout = 45 * time.Second

	openedPathsPreparingStatus = "Preparing iCloud files"
	openedPathsTimeoutStatus   = "Some iCloud files are not downloaded"
)

var openedPathPollInterval = 200 * time.Millisecond

type openedPathReadinessState int

const (
	openedPathReady openedPathReadinessState = iota
	openedPathPending
	openedPathMissing
	openedPathError
)

type openedPathReadiness struct {
	Path  string
	State openedPathReadinessState
	Err   error
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

func (r openedPathReadinessResult) readyPaths() []string {
	out := make([]string, 0, len(r))
	for _, item := range r {
		if item.State == openedPathReady {
			out = append(out, item.Path)
		}
	}
	return out
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

func defaultOpenedPathReadiness(ctx context.Context, paths []string) openedPathReadinessResult {
	result := make(openedPathReadinessResult, 0, len(paths))
	for _, path := range paths {
		if ctx.Err() != nil {
			return result
		}

		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				result = append(result, openedPathReadiness{Path: path, State: openedPathMissing, Err: err})
			} else {
				result = append(result, openedPathReadiness{Path: path, State: openedPathError, Err: err})
			}
			continue
		}

		result = append(result, openedPathReadiness{Path: path, State: openedPathReady})
	}
	return result
}

func (a *App) cancelOpenedPathReadiness() {
	a.openReadinessMu.Lock()
	cancel := a.openReadinessCancel
	a.openReadinessGeneration++
	a.openReadinessCancel = nil
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (a *App) beginOpenedPathReadiness() (context.Context, uint64) {
	ctx, cancel := context.WithCancel(context.Background())

	a.openReadinessMu.Lock()
	previousCancel := a.openReadinessCancel
	a.openReadinessGeneration++
	generation := a.openReadinessGeneration
	a.openReadinessCancel = cancel
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
	} else {
		cancel = nil
	}
	a.openReadinessMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (a *App) applyOpenedPaths(paths []string) {
	normalized := normalizeOpenedPaths(paths)
	if len(normalized) == 0 {
		return
	}

	ctx, generation := a.beginOpenedPathReadiness()
	go a.waitForOpenedPathsAndApply(ctx, generation, normalized)
}

func (a *App) waitForOpenedPathsAndApply(ctx context.Context, generation uint64, paths []string) {
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
		if result.allReady() {
			a.applyReadyOpenedPaths(generation, paths)
			return
		}

		fyne.Do(func() {
			if !a.isOpenedPathReadinessCurrent(generation) {
				return
			}
			a.State.MainStatus = openedPathsPreparingStatus
			a.State.MainStatusColor = util.YELLOW
			a.refreshUI()
		})

		if sleepOrCancel(ctx, openedPathPollInterval) {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				a.applyOpenedPathReadinessTimeout(generation)
			}
			return
		}
	}
}

func (a *App) applyReadyOpenedPaths(generation uint64, paths []string) {
	fyne.Do(func() {
		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}

		snap := a.State.UISnapshot()
		if snap.Working || snap.Scanning {
			a.finishOpenedPathReadiness(generation)
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.applyStartupPaths(paths)
	})
}

func (a *App) applyOpenedPathReadinessError(generation uint64) {
	fyne.Do(func() {
		if !a.isOpenedPathReadinessCurrent(generation) {
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
		if !a.isOpenedPathReadinessCurrent(generation) {
			return
		}

		a.finishOpenedPathReadiness(generation)
		a.State.MainStatus = openedPathsTimeoutStatus
		a.State.MainStatusColor = util.YELLOW
		a.refreshUI()
	})
}
