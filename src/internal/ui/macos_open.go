// Platform-neutral side of the macOS "open file" bridge.
//
// On darwin, AppleEvents (Finder double-click, drag onto the app/dock icon) are
// delivered to goAppendOpenedPath in macos_open_darwin.go, which forwards each
// path to appendOpenedPath here. Buffering and delivery live in this file — not
// the darwin file — so the delivery logic is unit-testable on every CI platform,
// not only macOS.
//
// Delivery is event-driven: appendOpenedPath fires a notify handler registered
// by the running App via setOpenedPathsNotify. This lets paths that arrive while
// the app is already running (issue #127: warm application:openURLs: events, and
// cold-launch events delivered after the first drain) reach the UI instead of
// sitting in the buffer indefinitely.
package ui

import "sync"

var (
	openedPathsMu     sync.Mutex
	openedPaths       []string
	openedPathsNotify func()
)

// appendOpenedPath buffers a path opened via the OS (AppleEvents on darwin) and
// invokes the registered notify handler, if any, so the path can be drained and
// applied. The handler is called outside the lock to avoid re-entrancy on
// openedPathsMu.
func appendOpenedPath(path string) {
	if path == "" {
		return
	}
	openedPathsMu.Lock()
	openedPaths = append(openedPaths, path)
	notify := openedPathsNotify
	openedPathsMu.Unlock()

	if notify != nil {
		notify()
	}
}

// setOpenedPathsNotify registers (or clears, when fn is nil) the handler invoked
// after a path is buffered. Callers should drain once immediately after
// registering so paths buffered before registration are not missed.
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
