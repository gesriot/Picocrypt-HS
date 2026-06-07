//go:build !darwin

package ui

import (
	"context"
	"os"
)

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
