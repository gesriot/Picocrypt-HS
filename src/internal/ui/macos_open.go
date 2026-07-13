// Platform-neutral side of the macOS "open file" bridge.
//
// On darwin, AppleEvents (Finder double-click, drag onto the app/dock icon) are
// delivered to goAppendOpenedPath in macos_open_darwin.go, which forwards each
// path to appendOpenedPath here and then calls flushOpenedPaths exactly once per
// application:openURLs: event. Buffering and delivery live in this file — not the
// darwin file — so the delivery logic is unit-testable on every CI platform, not
// only macOS.
//
// Delivery is event-driven and batched. The darwin bridge buffers every path in
// one application:openURLs: callback and calls flushOpenedPaths after the array
// has been appended. flushOpenedPaths then coalesces any nearby callbacks before
// notifying the UI, because Finder/Dock can split one user drag into smaller
// openURLs: batches. That guarantees one drain -> one onDrop carrying the full
// observed selection instead of replacing earlier batches or discarding later
// ones through onDrop's scanning guard (issue #127).
//
// The notify handler is registered by the running App via setOpenedPathsNotify.
// This also lets paths that arrive while the app is already running (issue #127:
// warm openURLs events, and cold-launch events delivered after the first drain)
// reach the UI instead of sitting in the buffer indefinitely.

package ui

import (
	"sync"
	"time"
)

var (
	openedPathsMu         sync.Mutex
	openedPaths           []string
	openedPathsNotify     func()
	openedPathsFlushTimer *time.Timer
	openedPathsFlushDelay = 200 * time.Millisecond
	openedPathsGeneration uint64
	openedPathsStopping   bool
	openedPathsInFlight   int
	openedPathsIdle       = sync.NewCond(&openedPathsMu)
)

// appendOpenedPath buffers a path opened via the OS (AppleEvents on darwin). It
// deliberately does not notify: the darwin bridge appends every URL from the
// current openURLs: callback first, then calls flushOpenedPaths once.
func appendOpenedPath(path string) {
	if path == "" {
		return
	}
	openedPathsMu.Lock()
	openedPaths = append(openedPaths, path)
	openedPathsMu.Unlock()
}

// flushOpenedPaths schedules the registered notify handler after a short quiet
// window. Finder/Dock may split one human drag onto the app icon into several
// openURLs: deliveries, so every delivery resets the timer and the UI drains the
// accumulated paths once the stream goes idle.
//
// It is a no-op when no handler is registered yet (a cold launch whose openURLs
// event arrives before the App wires its handler) — those paths stay buffered
// until startup registers the handler and arms the debounce timer.
func flushOpenedPaths() {
	openedPathsMu.Lock()
	if openedPathsStopping || openedPathsNotify == nil {
		openedPathsMu.Unlock()
		return
	}
	if openedPathsFlushTimer != nil {
		openedPathsFlushTimer.Stop()
	}
	openedPathsGeneration++
	generation := openedPathsGeneration
	openedPathsFlushTimer = time.AfterFunc(openedPathsFlushDelay, func() {
		notifyOpenedPaths(generation)
	})
	openedPathsMu.Unlock()
}

func notifyOpenedPaths(generation uint64) {
	openedPathsMu.Lock()
	if openedPathsStopping || generation != openedPathsGeneration || openedPathsNotify == nil {
		openedPathsMu.Unlock()
		return
	}
	openedPathsInFlight++
	notify := openedPathsNotify
	openedPathsFlushTimer = nil
	openedPathsMu.Unlock()

	defer func() {
		openedPathsMu.Lock()
		openedPathsInFlight--
		if openedPathsInFlight == 0 {
			openedPathsIdle.Broadcast()
		}
		openedPathsMu.Unlock()
	}()
	notify()
}

func hasOpenedPaths() bool {
	openedPathsMu.Lock()
	defer openedPathsMu.Unlock()
	return len(openedPaths) > 0
}

// setOpenedPathsNotify registers (or clears, when fn is nil) the handler invoked
// by flushOpenedPaths. Callers should call flushOpenedPaths after registering if
// paths were buffered before registration.
func setOpenedPathsNotify(fn func()) {
	openedPathsMu.Lock()
	if fn != nil && openedPathsStopping {
		openedPathsMu.Unlock()
		return
	}
	if fn == nil && openedPathsFlushTimer != nil {
		openedPathsFlushTimer.Stop()
		openedPathsFlushTimer = nil
	}
	if fn == nil {
		openedPathsGeneration++
	}
	openedPathsNotify = fn
	openedPathsMu.Unlock()
}

// prepareOpenedPathsNotify starts a new application notification session. It
// is called before the app registers any lifecycle callbacks.
func prepareOpenedPathsNotify() {
	openedPathsMu.Lock()
	if openedPathsFlushTimer != nil {
		openedPathsFlushTimer.Stop()
		openedPathsFlushTimer = nil
	}
	openedPathsGeneration++
	openedPathsNotify = nil
	openedPathsStopping = false
	openedPathsMu.Unlock()
}

func stopOpenedPathsNotify() {
	openedPathsMu.Lock()
	openedPathsStopping = true
	if openedPathsFlushTimer != nil {
		openedPathsFlushTimer.Stop()
		openedPathsFlushTimer = nil
	}
	openedPathsGeneration++
	openedPathsNotify = nil
	openedPathsMu.Unlock()
}

func waitOpenedPathsNotifyIdle() {
	openedPathsMu.Lock()
	for openedPathsInFlight > 0 {
		openedPathsIdle.Wait()
	}
	openedPathsMu.Unlock()
}

// drainOpenedPaths returns the buffered paths and clears the buffer, or nil when
// empty. On non-darwin the buffer is always empty (nothing calls appendOpenedPath).
func drainOpenedPaths() []string {
	openedPathsMu.Lock()
	defer openedPathsMu.Unlock()
	if len(openedPaths) == 0 {
		return nil
	}
	out := make([]string, len(openedPaths))
	copy(out, openedPaths)
	openedPaths = openedPaths[:0]
	return out
}
