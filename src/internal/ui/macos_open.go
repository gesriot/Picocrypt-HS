// Platform-neutral side of the macOS "open file" bridge.
//
// On darwin, AppleEvents (Finder double-click, drag onto the app/dock icon) are
// delivered to goAppendOpenedPath in macos_open_darwin.go, which forwards each
// path to appendOpenedPath here and then calls flushOpenedPaths exactly once per
// application:openURLs: event. Buffering and delivery live in this file — not the
// darwin file — so the delivery logic is unit-testable on every CI platform, not
// only macOS.
//
// Delivery is event-driven and batched. AppKit hands an entire multi-file open
// gesture to application:openURLs: as a single [URL] array — one delegate call,
// per Apple's NSApplicationDelegate contract — so the bridge buffers every path
// in that array and fires the notify handler once, via flushOpenedPaths, after
// the whole array has been appended. That guarantees one drain -> one onDrop
// carrying the entire selection. The previous behaviour notified after every
// single path, which shredded one gesture into N single-path onDrop calls: each
// replaced the prior selection or was discarded by onDrop's scanning guard,
// losing files (issue #127).
//
// The notify handler is registered by the running App via setOpenedPathsNotify.
// This also lets paths that arrive while the app is already running (issue #127:
// warm openURLs events, and cold-launch events delivered after the first drain)
// reach the UI instead of sitting in the buffer indefinitely.
package ui

import "sync"

var (
	openedPathsMu     sync.Mutex
	openedPaths       []string
	openedPathsNotify func()
)

// appendOpenedPath buffers a path opened via the OS (AppleEvents on darwin). It
// deliberately does not notify: a single openURLs: event delivers several paths,
// so the darwin bridge appends them all and then calls flushOpenedPaths once,
// ensuring the whole gesture reaches the UI as one drop rather than one per path.
func appendOpenedPath(path string) {
	if path == "" {
		return
	}
	openedPathsMu.Lock()
	openedPaths = append(openedPaths, path)
	openedPathsMu.Unlock()
}

// flushOpenedPaths invokes the registered notify handler once, after a batch of
// appendOpenedPath calls, so the buffered paths are drained and applied together.
// It is a no-op when no handler is registered yet (a cold launch whose openURLs
// event arrives before the App wires its handler) — those paths are picked up by
// the initial drain performed right after setOpenedPathsNotify registers. The
// handler is invoked outside the lock to avoid re-entrancy on openedPathsMu.
func flushOpenedPaths() {
	openedPathsMu.Lock()
	notify := openedPathsNotify
	openedPathsMu.Unlock()

	if notify != nil {
		notify()
	}
}

// setOpenedPathsNotify registers (or clears, when fn is nil) the handler invoked
// by flushOpenedPaths. Callers should drain once immediately after registering so
// paths buffered before registration are not missed.
func setOpenedPathsNotify(fn func()) {
	openedPathsMu.Lock()
	openedPathsNotify = fn
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
