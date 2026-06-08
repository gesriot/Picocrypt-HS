//go:build linux && !android

package ui

const linuxAppID = "io.github.picocrypt_ng.Picocrypt-NG"
const linuxX11WMClass = "Picocrypt-NG"

func runtimeAppID() string {
	return linuxAppID
}
