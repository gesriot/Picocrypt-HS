//go:build js && wasm

package main

import (
	"bytes"
	"strings"
	"syscall/js"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

// Pins the bridge error code: non-zero and distinct from internal/wasm 1-5.
func TestInvalidArgErrorCodeContract(t *testing.T) {
	if errInvalidArg == 0 {
		t.Fatal("errInvalidArg must be non-zero")
	}
	for _, c := range []int{1, 2, 3, 4, 5} {
		if errInvalidArg == c {
			t.Fatalf("errInvalidArg=%d collides with internal/wasm code %d", errInvalidArg, c)
		}
	}
}

// codeOf extracts result.code from a bridge return; -1 if the shape is wrong.
func codeOf(v any) int {
	jv, ok := v.(js.Value)
	if !ok || jv.Type() != js.TypeObject {
		return -1
	}
	c := jv.Get("code")
	if c.Type() != js.TypeNumber {
		return -1
	}
	return c.Int()
}

func newOpts(fields map[string]any) js.Value {
	o := js.Global().Get("Object").New()
	for k, val := range fields {
		o.Set(k, val)
	}
	return o
}

// Malformed inputs must return {code: errInvalidArg}, never panic out of FuncOf.
func TestBridgeRejectsBadInput(t *testing.T) {
	u8 := js.Global().Get("Uint8Array").New(4)
	cases := []struct {
		name string
		arg  js.Value
	}{
		{"non-object arg", js.ValueOf(42)},
		{"missing data", newOpts(map[string]any{"password": "pw"})},
		{"data not uint8array", newOpts(map[string]any{"data": "nope", "password": "pw"})},
		{"missing password", newOpts(map[string]any{"data": u8})},
		{"password not string", newOpts(map[string]any{"data": u8, "password": 7})},
	}
	for _, cb := range []struct {
		name string
		fn   func(js.Value, []js.Value) any
	}{{"encrypt", encrypt}, {"decrypt", decrypt}} {
		for _, tc := range cases {
			t.Run(cb.name+"/"+tc.name, func(t *testing.T) {
				if got := codeOf(cb.fn(js.Undefined(), []js.Value{tc.arg})); got != errInvalidArg {
					t.Fatalf("%s(%s) code=%d; want errInvalidArg=%d", cb.name, tc.name, got, errInvalidArg)
				}
			})
		}
	}
}

// Over-long comments are rejected at the bridge with errInvalidArg.
func TestBridgeRejectsLongComments(t *testing.T) {
	u8 := js.Global().Get("Uint8Array").New(4)
	long := []byte(strings.Repeat("a", 100000)) // > header.MaxCommentLen (99999)
	arg := newOpts(map[string]any{"data": u8, "password": "pw", "comments": string(long)})
	if got := codeOf(encrypt(js.Undefined(), []js.Value{arg})); got != errInvalidArg {
		t.Fatalf("over-long comments code=%d; want errInvalidArg=%d", got, errInvalidArg)
	}
}

// readKeyfiles must reject a non-array and a non-Uint8Array element.
func TestReadKeyfilesRejectsBadShapes(t *testing.T) {
	if _, ok := readKeyfiles(js.ValueOf("nope")); ok {
		t.Fatal("non-array keyfiles accepted")
	}
	arr := js.Global().Get("Array").New()
	arr.Call("push", js.ValueOf(42)) // not a Uint8Array
	if _, ok := readKeyfiles(arr); ok {
		t.Fatal("non-Uint8Array keyfile element accepted")
	}
}

// readKeyfiles(undefined) and readKeyfiles(null) must both return (nil, true):
// no keyfiles, ok — exercising the IsUndefined/IsNull early-return paths.
func TestReadKeyfilesNilIsOK(t *testing.T) {
	if kfs, ok := readKeyfiles(js.Undefined()); !ok || kfs != nil {
		t.Fatalf("readKeyfiles(undefined) = (%v, %v); want (nil, true)", kfs, ok)
	}
	if kfs, ok := readKeyfiles(js.Null()); !ok || kfs != nil {
		t.Fatalf("readKeyfiles(null) = (%v, %v); want (nil, true)", kfs, ok)
	}
}

func TestBridgeKeyfileRoundTrip(t *testing.T) {
	mkU8 := func(b []byte) js.Value {
		u := js.Global().Get("Uint8Array").New(len(b))
		js.CopyBytesToJS(u, b)
		return u
	}
	plain := mkU8([]byte("keyfile bridge round trip"))
	kf := js.Global().Get("Array").New()
	kf.Call("push", mkU8([]byte("kf-1")))
	kf.Call("push", mkU8([]byte("kf-2")))

	enc := encrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": plain, "password": "pw", "keyfiles": kf, "keyfileOrdered": true,
	})}).(js.Value)
	if enc.Get("code").Int() != 0 {
		t.Fatalf("encrypt code=%d", enc.Get("code").Int())
	}
	// Missing keyfiles on decrypt → code 7.
	miss := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": enc.Get("data"), "password": "pw",
	})}).(js.Value)
	if miss.Get("code").Int() != 7 {
		t.Fatalf("missing-keyfiles code=%d; want 7", miss.Get("code").Int())
	}
	// Correct keyfiles → success.
	dec := decrypt(js.Undefined(), []js.Value{newOpts(map[string]any{
		"data": enc.Get("data"), "password": "pw", "keyfiles": kf,
	})}).(js.Value)
	if dec.Get("code").Int() != 0 {
		t.Fatalf("decrypt code=%d; want 0", dec.Get("code").Int())
	}
}

func TestBridgeEncryptReedSolomonSetsHeaderFlag(t *testing.T) {
	opts := js.Global().Get("Object").New()
	opts.Set("data", js.Global().Get("Uint8Array").New(64))
	opts.Set("password", "bridge-rs")
	opts.Set("reedSolomon", true)

	rv := encrypt(js.Undefined(), []js.Value{opts}).(js.Value)
	if code := rv.Get("code").Int(); code != 0 {
		t.Fatalf("encrypt code %d", code)
	}

	out := rv.Get("data")
	volBytes := make([]byte, out.Get("length").Int())
	js.CopyBytesToGo(volBytes, out)

	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	res, err := header.NewReader(bytes.NewReader(volBytes), rs).ReadHeader()
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	if !res.Header.Flags.ReedSolomon {
		t.Fatal("reedSolomon option did not set the header RS flag")
	}
}

// A valid encrypt then decrypt round-trips through the bridge objects, carrying comments.
func TestBridgeRoundTrip(t *testing.T) {
	plain := []byte("bridge round trip")
	u8 := js.Global().Get("Uint8Array").New(len(plain))
	js.CopyBytesToJS(u8, plain)

	encArg := newOpts(map[string]any{"data": u8, "password": "pw", "paranoid": true, "comments": "hi"})
	encRes := encrypt(js.Undefined(), []js.Value{encArg}).(js.Value)
	if encRes.Get("code").Int() != 0 {
		t.Fatalf("encrypt code=%d; want 0", encRes.Get("code").Int())
	}

	decArg := newOpts(map[string]any{"data": encRes.Get("data"), "password": "pw"})
	decRes := decrypt(js.Undefined(), []js.Value{decArg}).(js.Value)
	if decRes.Get("code").Int() != 0 {
		t.Fatalf("decrypt code=%d; want 0", decRes.Get("code").Int())
	}
	if decRes.Get("comments").String() != "hi" {
		t.Fatalf("comments=%q; want %q", decRes.Get("comments").String(), "hi")
	}
	out := decRes.Get("data")
	got := make([]byte, out.Get("length").Int())
	js.CopyBytesToGo(got, out)
	if string(got) != string(plain) {
		t.Fatalf("round-trip data=%q; want %q", got, plain)
	}
}
