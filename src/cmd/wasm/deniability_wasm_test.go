//go:build js && wasm

package main

import (
	"bytes"
	"syscall/js"
	"testing"

	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
)

func mkU8Den(b []byte) js.Value {
	u := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u, b)
	return u
}

func dataBytesDen(t *testing.T, res any) []byte {
	t.Helper()
	jv := res.(js.Value)
	d := jv.Get("data")
	out := make([]byte, d.Get("length").Int())
	js.CopyBytesToGo(out, d)
	return out
}

// The bridge must forward `deniability:true`: the produced volume must have NO
// readable header (disguised as random data) AND still decrypt back to the
// original through the same bridge. The no-readable-header assertion is what
// makes this fail if the bridge silently drops the option (a normal volume,
// which has a decodable version, would otherwise also roundtrip).
func TestBridgeDeniabilityRoundtrip(t *testing.T) {
	original := []byte("bridge deniability roundtrip payload")
	password := "bridge-deniability-pw"

	encOpts := js.Global().Get("Object").New()
	encOpts.Set("data", mkU8Den(original))
	encOpts.Set("password", password)
	encOpts.Set("deniability", true)

	encRes := encrypt(js.Undefined(), []js.Value{encOpts})
	if code := encRes.(js.Value).Get("code").Int(); code != 0 {
		t.Fatalf("encrypt code %d; want 0", code)
	}
	wrapped := dataBytesDen(t, encRes)

	// A deniable volume has no readable header: the first 15 bytes must NOT decode
	// to a valid version (decode may succeed on random bytes, so check MatchVersion).
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	if vd, derr := encoding.Decode(rs.RS5, append([]byte(nil), wrapped[:15]...), false); derr == nil && header.MatchVersion(vd) {
		t.Fatal("bridge produced a decodable header — deniability option was not forwarded")
	}

	decOpts := js.Global().Get("Object").New()
	decOpts.Set("data", mkU8Den(wrapped))
	decOpts.Set("password", password)

	decRes := decrypt(js.Undefined(), []js.Value{decOpts})
	if code := decRes.(js.Value).Get("code").Int(); code != 0 {
		t.Fatalf("decrypt code %d; want 0", code)
	}
	if got := dataBytesDen(t, decRes); !bytes.Equal(got, original) {
		t.Fatalf("bridge roundtrip mismatch\ngot:  %q\nwant: %q", got, original)
	}
}
