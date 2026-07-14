package ui

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func resetOpenedPathsForTest(t *testing.T) {
	t.Helper()
	prepareOpenedPathsNotify()
	setOpenedPathsNotify(nil)
	drainOpenedPaths()
	t.Cleanup(func() {
		prepareOpenedPathsNotify()
		setOpenedPathsNotify(nil)
		drainOpenedPaths()
	})
}

func withOpenedPathsFlushDelay(t *testing.T, delay time.Duration) {
	t.Helper()
	oldDelay := openedPathsFlushDelay
	openedPathsFlushDelay = delay
	t.Cleanup(func() {
		openedPathsFlushDelay = oldDelay
	})
}

func TestFlushOpenedPathsCoalescesRapidBatchesIntoOneNotify(t *testing.T) {
	resetOpenedPathsForTest(t)
	withOpenedPathsFlushDelay(t, 10*time.Millisecond)

	var mu sync.Mutex
	var batches [][]string
	setOpenedPathsNotify(func() {
		drained := drainOpenedPaths()
		mu.Lock()
		batches = append(batches, drained)
		mu.Unlock()
	})

	paths := []string{"/tmp/a.txt", "/tmp/b.txt", "/tmp/c.txt"}
	appendOpenedPath(paths[0])
	appendOpenedPath(paths[1])
	flushOpenedPaths()
	appendOpenedPath(paths[2])
	flushOpenedPaths()

	deadline := time.After(500 * time.Millisecond)
	for {
		mu.Lock()
		done := len(batches) > 0
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for opened paths notification")
		case <-time.After(5 * time.Millisecond):
		}
	}

	mu.Lock()
	got := append([][]string(nil), batches...)
	mu.Unlock()

	if len(got) != 1 {
		t.Fatalf("notify fired %d time(s) for split open batches; want exactly 1 batch: %#v", len(got), got)
	}
	if !reflect.DeepEqual(got[0], paths) {
		t.Fatalf("drained paths = %#v; want %#v", got[0], paths)
	}
}

func TestClearingOpenedPathsNotifyCancelsPendingBatch(t *testing.T) {
	resetOpenedPathsForTest(t)
	withOpenedPathsFlushDelay(t, time.Hour)

	called := false
	setOpenedPathsNotify(func() {
		called = true
	})

	appendOpenedPath("/tmp/a.txt")
	flushOpenedPaths()
	setOpenedPathsNotify(nil)
	openedPathsMu.Lock()
	staleGeneration := openedPathsGeneration - 1
	openedPathsMu.Unlock()
	notifyOpenedPaths(staleGeneration)

	if called {
		t.Fatal("notify fired after handler was cleared")
	}
	if got := drainOpenedPaths(); !reflect.DeepEqual(got, []string{"/tmp/a.txt"}) {
		t.Fatalf("drained paths after cancelled notify = %#v; want buffered path preserved", got)
	}
}
