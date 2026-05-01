//go:build !darwin

package ui

func drainOpenedPaths() []string { return nil }
