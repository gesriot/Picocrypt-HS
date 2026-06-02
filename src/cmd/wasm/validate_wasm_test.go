//go:build js && wasm

package main

import (
	"syscall/js"
	"testing"
)

// These tests run under a live JS host via the wasm exec shim, e.g.:
//
//	cd src && GOOS=js GOARCH=wasm go test ./cmd/wasm/ \
//	    -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec"
//
// The //go:build js && wasm tag excludes them from a normal `go test ./...`, so
// they only ever execute where syscall/js is real. No node on PATH => the exec
// shim cannot run them at all (they are skipped by absence, never silently
// passed).

// TestInvalidArgErrorCodeContract pins the bridge-level error code returned to
// JS for a malformed argument. WHY: the consuming website detects failure via
// `typeof result === 'number'` and maps the internal/wasm codes 1-5; a new
// malformed-argument code must stay a non-zero number distinct from 1-5 so the
// site still treats it as failure (not success, not a hang).
func TestInvalidArgErrorCodeContract(t *testing.T) {
	if errInvalidArg == 0 {
		t.Fatal("errInvalidArg must be non-zero so JS sees an error number, not success")
	}
	for _, c := range []int{1, 2, 3, 4, 5} {
		if errInvalidArg == c {
			t.Fatalf("errInvalidArg=%d collides with internal/wasm code %d", errInvalidArg, c)
		}
	}
}

// TestValidateArgsArity locks the arity gate: fewer than two arguments is
// rejected before any js.Value field access (which would panic).
func TestValidateArgsArity(t *testing.T) {
	if validateArgs([]js.Value{}) {
		t.Fatal("validateArgs must reject zero args")
	}
	if validateArgs([]js.Value{js.Undefined()}) {
		t.Fatal("validateArgs must reject fewer than 2 args")
	}
}

// TestValidateArgsRejectsBadShapes locks the type gate: args[0] must be a real
// Uint8Array and args[1] must be a string. Each rejected shape here is one that
// would otherwise drive args[0].Get("length").Int() / CopyBytesToGo into a
// panic and kill the instance.
func TestValidateArgsRejectsBadShapes(t *testing.T) {
	validData := js.Global().Get("Uint8Array").New(4)
	cases := []struct {
		name string
		a0   js.Value
		a1   js.Value
	}{
		{"null data", js.Null(), js.ValueOf("pw")},
		{"undefined data", js.Undefined(), js.ValueOf("pw")},
		{"number data", js.ValueOf(42), js.ValueOf("pw")},
		{"string data", js.ValueOf("not-bytes"), js.ValueOf("pw")},
		{"wrong typed array", js.Global().Get("Int8Array").New(4), js.ValueOf("pw")},
		{"non-string password", validData, js.ValueOf(42)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if validateArgs([]js.Value{tc.a0, tc.a1}) {
				t.Fatalf("validateArgs accepted invalid args (%s)", tc.name)
			}
		})
	}
}

// TestValidateArgsAcceptsValid ensures the gate does not reject a legitimate
// (Uint8Array, string) pair.
func TestValidateArgsAcceptsValid(t *testing.T) {
	if !validateArgs([]js.Value{js.Global().Get("Uint8Array").New(4), js.ValueOf("pw")}) {
		t.Fatal("validateArgs rejected a valid (Uint8Array, string) pair")
	}
}

// TestCallbacksDoNotCrashOnBadArg is the core DoS regression: a malformed
// argument that on HEAD drives args[0].Get("length").Int() to panic out of the
// js.FuncOf trampoline (permanently killing the WASM instance, with main()
// parked on <-make(chan struct{}) and no recovery short of page reload) must
// instead return the int errInvalidArg and leave the instance alive. The test
// invokes the exported callbacks directly with a number where a Uint8Array is
// expected and asserts a clean int return — proving no panic escaped.
func TestCallbacksDoNotCrashOnBadArg(t *testing.T) {
	badArgs := []js.Value{js.ValueOf(42), js.ValueOf("pw")}
	callbacks := []struct {
		name string
		fn   func(js.Value, []js.Value) any
	}{
		{"encrypt", encrypt},
		{"decrypt", decrypt},
	}
	for _, cb := range callbacks {
		t.Run(cb.name, func(t *testing.T) {
			got := cb.fn(js.Undefined(), badArgs)
			n, ok := got.(int)
			if !ok {
				t.Fatalf("%s(badArg) returned %T (%v); want int errInvalidArg", cb.name, got, got)
			}
			if n != errInvalidArg {
				t.Fatalf("%s(badArg)=%d; want errInvalidArg=%d", cb.name, n, errInvalidArg)
			}
		})
	}
}

// The recover() defers in encrypt/decrypt are a forward-looking backstop for a
// Go panic occurring between validation and use. They are not separately unit
// tested here because, once validateArgs has accepted the arguments, a genuine
// Uint8Array drives no panic at all, and the only "instanceof Uint8Array but not
// a real typed array" shape (e.g. Object.create(Uint8Array.prototype)) throws a
// JS host exception inside syscall/js when its length getter runs — that is not a
// Go panic and recover() cannot intercept it. Such a shape can only come from
// adversarial same-origin JS; the consuming site's contract passes a real
// Uint8Array. The realistic malformed-argument cases are covered by
// TestValidateArgsRejectsBadShapes and TestCallbacksDoNotCrashOnBadArg above.
