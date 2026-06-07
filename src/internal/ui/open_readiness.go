package ui

import (
	"context"
	"errors"
	"os"
	"time"
)

const (
	openedPathPollInterval = 200 * time.Millisecond
	openedPathReadyTimeout = 45 * time.Second

	openedPathsPreparingStatus = "Preparing iCloud files"
	openedPathsTimeoutStatus   = "Some iCloud files are not downloaded"
)

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
