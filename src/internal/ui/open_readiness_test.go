package ui

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestNormalizeOpenedPathsFiltersProcessSerialAndDedupesInOrder(t *testing.T) {
	got := normalizeOpenedPaths([]string{
		"-psn_0_12345",
		"/tmp/a.txt",
		"",
		"/tmp/b.txt",
		"/tmp/a.txt",
	})
	want := []string{"/tmp/a.txt", "/tmp/b.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeOpenedPaths() = %#v; want %#v", got, want)
	}
}

func TestOpenedPathReadinessResultRequiresAllCurrent(t *testing.T) {
	ready := openedPathReadinessResult{
		{Path: "/tmp/current.txt", State: openedPathReady},
		{Path: "/tmp/stale.txt", State: openedPathPending},
	}
	if ready.allReady() {
		t.Fatal("allReady() = true with a pending path; want false")
	}
	if got := ready.readyPaths(); !reflect.DeepEqual(got, []string{"/tmp/current.txt"}) {
		t.Fatalf("readyPaths() = %#v; want only current path", got)
	}
}

func TestOpenedPathReadinessResultReportsTerminalErrors(t *testing.T) {
	errAccess := errors.New("permission denied")
	result := openedPathReadinessResult{
		{Path: "/tmp/a.txt", State: openedPathReady},
		{Path: "/tmp/blocked.txt", State: openedPathError, Err: errAccess},
	}
	if result.terminalError() == nil {
		t.Fatal("terminalError() = nil; want access error")
	}
}

func TestSleepOrCancelStopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !sleepOrCancel(ctx, time.Hour) {
		t.Fatal("sleepOrCancel() = false after cancellation; want true")
	}
}
