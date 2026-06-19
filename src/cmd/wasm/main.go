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

// errInvalidArg is the bridge-level error code returned to JS when an exported
// callback is invoked with a malformed argument (wrong arity, a non-Uint8Array
// data argument, or a non-string password). It is a non-zero number distinct
// from the internal/wasm pipeline codes 1-5 so the consuming site keeps
// detecting failure via `typeof result === 'number'`.
const errInvalidArg = 6

// validateArgs reports whether args carries the expected (Uint8Array, string)
// pair. It performs every check via type predicates that cannot panic, so it is
// safe to call before any args[0].Get/CopyBytesToGo access. A malformed call
// from JS (null, a number, a non-Uint8Array typed array, a missing password)
// is rejected here instead of crashing the instance.
func validateArgs(args []js.Value) bool {
	if len(args) < 2 {
		return false
	}
	if !args[0].InstanceOf(js.Global().Get("Uint8Array")) {
		return false
	}
	return args[1].Type() == js.TypeString
}

// args[0] = Uint8Array, args[1] = password string
// returns Uint8Array (0 prefix + plaintext) or error code int
func decrypt(this js.Value, args []js.Value) (result any) {
	// Recover from any panic so a malformed js.Value cannot escape FuncOf and
	// kill the WASM instance; return the same error code the caller handles.
	defer func() {
		if r := recover(); r != nil {
			result = errInvalidArg
		}
	}()

	if !validateArgs(args) {
		return errInvalidArg
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

	plaintext, errCode := wasm.DecryptVolume(fileData, passwordBytes)
	if errCode != 0 {
		return errCode
	}
	defer crypto.SecureZero(plaintext)

	out := js.Global().Get("Uint8Array").New(len(plaintext) + 1)
	resultData := make([]byte, len(plaintext)+1)
	defer crypto.SecureZero(resultData)
	resultData[0] = 0
	copy(resultData[1:], plaintext)
	js.CopyBytesToJS(out, resultData)
	return out
}

func encrypt(this js.Value, args []js.Value) (result any) {
	// Recover from any panic so a malformed js.Value cannot escape FuncOf and
	// kill the WASM instance; return the same error code the caller handles.
	defer func() {
		if r := recover(); r != nil {
			result = errInvalidArg
		}
	}()

	if !validateArgs(args) {
		return errInvalidArg
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

	ciphertext, errCode := wasm.EncryptVolume(fileData, passwordBytes, wasm.EncryptOptions{})
	if errCode != 0 {
		return errCode
	}
	defer crypto.SecureZero(ciphertext)

	out := js.Global().Get("Uint8Array").New(len(ciphertext) + 1)
	resultData := make([]byte, len(ciphertext)+1)
	defer crypto.SecureZero(resultData)
	resultData[0] = 0
	copy(resultData[1:], ciphertext)
	js.CopyBytesToJS(out, resultData)
	return out
}
