//go:build darwin

package ui

/*
#cgo CFLAGS: -fno-objc-arc
#cgo LDFLAGS: -framework Cocoa
*/
import "C"

// The Objective-C side of this bridge lives in macos_open_darwin.m (separate
// file because the preamble of a //export-using cgo file must contain only
// declarations, not definitions — putting @implementation here would generate
// duplicate ObjC symbols at link time).
//
// macos_open_darwin.m uses class_addMethod to inject application:openURLs:
// into GLFW's existing application delegate at +(void)load time, then calls
// goAppendOpenedPath below for each opened file URL. Buffering, notify, and
// drain logic lives in the platform-neutral macos_open.go so it is testable on
// every CI platform.

//export goAppendOpenedPath
func goAppendOpenedPath(cpath *C.char) {
	if cpath == nil {
		return
	}
	appendOpenedPath(C.GoString(cpath))
}
