//go:build js && wasm

package main

import (
	"syscall/js"

	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/wasm"
)

func main() {
	js.Global().Set("picocryptEncrypt", js.FuncOf(encrypt))
	js.Global().Set("picocryptDecrypt", js.FuncOf(decrypt))

	// Keep WASM alive
	<-make(chan struct{})
}

// args[0] = Uint8Array, args[1] = password string
// returns Uint8Array (0 prefix + plaintext) or error code int
func decrypt(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return 1
	}

	length := args[0].Get("length").Int()
	if length <= 0 || length > 1<<30 {
		return 1
	}

	fileData := make([]byte, length)
	js.CopyBytesToGo(fileData, args[0])
	defer crypto.SecureZero(fileData)

	passwordBytes := []byte(args[1].String())
	defer crypto.SecureZero(passwordBytes)

	plaintext, errCode := wasm.DecryptVolume(fileData, string(passwordBytes))
	if errCode != 0 {
		return errCode
	}
	defer crypto.SecureZero(plaintext)

	result := js.Global().Get("Uint8Array").New(len(plaintext) + 1)
	resultData := make([]byte, len(plaintext)+1)
	defer crypto.SecureZero(resultData)
	resultData[0] = 0
	copy(resultData[1:], plaintext)
	js.CopyBytesToJS(result, resultData)
	return result
}

func encrypt(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return 1
	}

	length := args[0].Get("length").Int()
	if length <= 0 || length > 1<<30 {
		return 1
	}

	fileData := make([]byte, length)
	js.CopyBytesToGo(fileData, args[0])
	defer crypto.SecureZero(fileData)

	passwordBytes := []byte(args[1].String())
	defer crypto.SecureZero(passwordBytes)

	ciphertext, errCode := wasm.EncryptVolume(fileData, string(passwordBytes))
	if errCode != 0 {
		return errCode
	}
	defer crypto.SecureZero(ciphertext)

	result := js.Global().Get("Uint8Array").New(len(ciphertext) + 1)
	resultData := make([]byte, len(ciphertext)+1)
	defer crypto.SecureZero(resultData)
	resultData[0] = 0
	copy(resultData[1:], ciphertext)
	js.CopyBytesToJS(result, resultData)
	return result
}
