//go:build darwin

package ui

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -framework Cocoa
*/
import "C"

import (
	"sync"
)

// The Objective-C side of this bridge lives in macos_open_darwin.m (separate
// file because the preamble of a //export-using cgo file must contain only
// declarations, not definitions — putting @implementation here would generate
// duplicate ObjC symbols at link time).
//
// macos_open_darwin.m uses class_addMethod to inject application:openURLs:
// into GLFW's existing application delegate at +(void)load time, then calls
// goAppendOpenedPath below for each opened file URL.

var (
	openedPathsMu sync.Mutex
	openedPaths   []string
)

//export goAppendOpenedPath
func goAppendOpenedPath(cpath *C.char) {
	if cpath == nil {
		return
	}
	path := C.GoString(cpath)
	openedPathsMu.Lock()
	openedPaths = append(openedPaths, path)
	openedPathsMu.Unlock()
}

// drainOpenedPaths returns paths buffered from AppleEvents and clears the buffer.
// Safe to call from the Fyne main goroutine inside Lifecycle.SetOnStarted.
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
