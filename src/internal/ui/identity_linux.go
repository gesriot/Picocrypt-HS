//go:build linux && !android

package ui

const linuxAppID = "io.github.picocrypt_ng.Picocrypt-NG"

func runtimeAppID() string {
	return linuxAppID
}
