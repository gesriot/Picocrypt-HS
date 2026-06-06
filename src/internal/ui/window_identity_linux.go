//go:build linux && cgo && !android && !mobile && !ci && !noos && !tamago && !tinygo && !test_web_driver

package ui

import "github.com/go-gl/glfw/v3.3/glfw"

func prepareWindowIdentity() {
	glfw.WindowHintString(glfw.X11ClassName, linuxAppID)
	glfw.WindowHintString(glfw.X11InstanceName, linuxAppID)
}
