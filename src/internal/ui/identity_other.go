//go:build !linux || android

package ui

const nonLinuxAppID = "io.github.picocryptng.PicocryptNG"

func runtimeAppID() string {
	return nonLinuxAppID
}
