//go:build !linux || !cgo || android || mobile || ci || noos || tamago || tinygo || test_web_driver

package ui

func prepareWindowIdentity() {}
